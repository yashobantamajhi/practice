package org.example.handler;

import com.amazonaws.services.lambda.runtime.Context;
import com.amazonaws.services.lambda.runtime.RequestHandler;
import com.fasterxml.jackson.databind.JsonNode;
import com.fasterxml.jackson.databind.ObjectMapper;
import software.amazon.awssdk.services.apigateway.ApiGatewayClient;
import software.amazon.awssdk.services.apigateway.model.GetRestApisRequest;
import software.amazon.awssdk.services.apigateway.model.GetRestApisResponse;
import software.amazon.awssdk.services.apigatewayv2.ApiGatewayV2Client;
import software.amazon.awssdk.services.apigatewayv2.model.GetApisRequest;
import software.amazon.awssdk.services.apigatewayv2.model.GetApisResponse;
import software.amazon.awssdk.services.config.ConfigClient;
import software.amazon.awssdk.services.config.model.ComplianceType;
import software.amazon.awssdk.services.config.model.Evaluation;
import software.amazon.awssdk.services.config.model.PutEvaluationsRequest;
import software.amazon.awssdk.services.wafv2.Wafv2Client;
import software.amazon.awssdk.services.wafv2.model.*;

import java.time.Instant;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Optional;

public class ApiGatewayWafComplianceAllChecker implements RequestHandler<Object, Object> {

    private final ObjectMapper mapper = new ObjectMapper();
    private final Wafv2Client wafv2 = Wafv2Client.create();
    private final ApiGatewayClient apiGwRest = ApiGatewayClient.create();
    private final ApiGatewayV2Client apiGwHttp = ApiGatewayV2Client.create();
    private final ConfigClient configClient = ConfigClient.create();

    @Override
    public Object handleRequest(Object input, Context context) {
        context.getLogger().log("Lambda invoked with event: " + safeToString(input));

        String resultToken = extractResultToken(input, context);

        // 1) list APIs (REST)
        List<ApiRecord> apis = new ArrayList<>();
        try {
            String region = Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-1");
            // REST APIs (API Gateway v1)
            String position = null;
            do {
                GetRestApisResponse restResp = apiGwRest.getRestApis(GetRestApisRequest.builder()
                        .limit(500).position(position).build());
                restResp.items().forEach(api ->
                        apis.add(new ApiRecord(api.id(), "AWS::ApiGateway::RestApi",
                                String.format("arn:aws:apigateway:%s::/restapis/%s", region, api.id())))
                );
                position = restResp.position();
            } while (position != null && !position.isEmpty());
        } catch (Exception e) {
            context.getLogger().log("Error listing REST APIs: " + e.getMessage());
            // continue to try APIv2
        }

        // 2) list HTTP/WebSocket APIs (API Gateway v2)
        try {
            String region = Optional.ofNullable(System.getenv("AWS_REGION")).orElse("us-east-1");
            String nextToken = null;
            do {
                GetApisResponse v2Resp = apiGwHttp.getApis(GetApisRequest.builder()
                        .maxResults("500").nextToken(nextToken).build());
                v2Resp.items().forEach(api ->
                        apis.add(new ApiRecord(api.apiId(), "AWS::ApiGatewayV2::Api",
                                String.format("arn:aws:apigateway:%s::/apis/%s", region, api.apiId())))
                );
                nextToken = v2Resp.nextToken();
            } while (nextToken != null && !nextToken.isEmpty());
        } catch (Exception e) {
            context.getLogger().log("Error listing APIv2 APIs: " + e.getMessage());
        }

        context.getLogger().log("Found total APIs: " + apis.size());

        // 3) list all WAF WebACLs (REGIONAL)
        List<WebACLSummary> webAcls = new ArrayList<>();
        try {
            ListWebAcLsResponse wResp = wafv2.listWebACLs(ListWebAcLsRequest.builder().scope("REGIONAL").build());
            if (wResp.webACLs() != null) {
                webAcls.addAll(wResp.webACLs());
            }
        } catch (Exception e) {
            context.getLogger().log("Error listing WAFv2 WebACLs: " + e.getMessage());
        }

        // 4) For each API, check attachment and prepare evaluations
        List<Evaluation> evaluations = new ArrayList<>();
        Instant now = Instant.now();

        for (ApiRecord api : apis) {
            boolean compliant = false;
            try {
                for (WebACLSummary webAcl : webAcls) {
                    ListResourcesForWebAclResponse res = wafv2.listResourcesForWebACL(
                            ListResourcesForWebAclRequest.builder()
                                    .webACLArn(webAcl.arn())
                                    .resourceType("API_GATEWAY")
                                    .build()
                    );
                    if (res.resourceArns() != null && res.resourceArns().contains(api.arn())) {
                        compliant = true;
                        break;
                    }
                }
            } catch (Exception e) {
                // If WAF check fails for some WebACL, log and continue; mark NON_COMPLIANT to be safe
                context.getLogger().log(String.format("Error checking WAF attachments for API %s: %s", api.id(), e.getMessage()));
            }

            evaluations.add(Evaluation.builder()
                    .complianceResourceId(api.id())
                    .complianceResourceType(api.type())
                    .complianceType(compliant ? ComplianceType.COMPLIANT : ComplianceType.NON_COMPLIANT)
                    .annotation(compliant ? "WAFv2 WebACL attached (REGIONAL)" : "No WAFv2 WebACL attached")
                    .orderingTimestamp(now)
                    .build());
        }

        // AWS Config PutEvaluations supports up to 100 evaluations per call (as of typical limits).
        // We'll batch in 100s to be safe.
        final int BATCH = 100;
        for (int i = 0; i < evaluations.size(); i += BATCH) {
            int toIndex = Math.min(i + BATCH, evaluations.size());
            List<Evaluation> sub = evaluations.subList(i, toIndex);
            try {
                PutEvaluationsRequest putReq = PutEvaluationsRequest.builder()
                        .evaluations(sub)
                        .resultToken(resultToken)
                        .build();
                configClient.putEvaluations(putReq);
            } catch (Exception e) {
                context.getLogger().log("Error calling PutEvaluations: " + e.getMessage());
            }
        }

        context.getLogger().log("Completed evaluations: " + evaluations.size());
        return Collections.singletonMap("evaluations", evaluations.size());
    }

    private static String safeToString(Object obj) {
        try {
            return new ObjectMapper().writeValueAsString(obj);
        } catch (Exception e) {
            return String.valueOf(obj);
        }
    }

    private String extractResultToken(Object input, Context context) {
        try {
            // Event may be a Map (from Lambda invocation). We attempt to parse resultToken robustly.
            JsonNode root = mapper.valueToTree(input);
            if (root.has("resultToken")) {
                return root.get("resultToken").asText();
            } else {
                // For periodic triggers result token may be "No token" or empty; AWS requires some token string.
                return "No token";
            }
        } catch (Exception e) {
            context.getLogger().log("Unable to extract resultToken - defaulting to No token.");
            return "No token";
        }
    }

    // Simple record-like holder for API entries
    private static class ApiRecord {
        private final String id;
        private final String type;
        private final String arn;

        ApiRecord(String id, String type, String arn) {
            this.id = id;
            this.type = type;
            this.arn = arn;
        }

        String id() { return id; }
        String type() { return type; }
        String arn() { return arn; }
    }
}
