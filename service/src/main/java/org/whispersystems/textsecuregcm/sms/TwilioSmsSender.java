/*
 * Copyright (C) 2013 Open WhisperSystems
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Affero General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Affero General Public License for more details.
 *
 * You should have received a copy of the GNU Affero General Public License
 * along with this program.  If not, see <http://www.gnu.org/licenses/>.
 */
package org.whispersystems.textsecuregcm.sms;

import com.aliyuncs.CommonRequest;
import com.aliyuncs.CommonResponse;
import com.aliyuncs.DefaultAcsClient;
import com.aliyuncs.IAcsClient;
import com.aliyuncs.dyvmsapi.model.v20170525.SingleCallByTtsRequest;
import com.aliyuncs.dyvmsapi.model.v20170525.SingleCallByTtsResponse;
import com.aliyuncs.exceptions.ClientException;
import com.aliyuncs.http.MethodType;
import com.aliyuncs.profile.DefaultProfile;
import com.aliyuncs.profile.IClientProfile;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.fasterxml.jackson.annotation.JsonProperty;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.configuration.AliYunConfiguration;
import org.whispersystems.textsecuregcm.http.FaultTolerantHttpClient;
import org.whispersystems.textsecuregcm.http.FormDataBodyPublisher;
import org.whispersystems.textsecuregcm.util.Base64;
import org.whispersystems.textsecuregcm.util.Constants;
import org.whispersystems.textsecuregcm.util.SystemMapper;

import java.io.IOException;
import java.net.URI;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.util.*;
import java.util.concurrent.CompletableFuture;

import static com.codahale.metrics.MetricRegistry.name;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
public class TwilioSmsSender {

    private static final Logger logger = LoggerFactory.getLogger(TwilioSmsSender.class);

    private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
    private final Meter smsMeter = metricRegistry.meter(name(getClass(), "sms", "delivered"));
    private final Meter voxMeter = metricRegistry.meter(name(getClass(), "vox", "delivered"));
    private final Meter priceMeter = metricRegistry.meter(name(getClass(), "price"));

//    private final String accountId;
//    private final String accountToken;
//    private final ArrayList<String> numbers;
//    private final String messagingServicesId;
//    private final String localDomain;
//    private final Random random;
//
//    private final FaultTolerantHttpClient httpClient;
//    private final URI smsUri;
//    private final URI voxUri;

    private String AccessKeyId;

    private String AccessKeySecret;

    private String TemplateCode;

    private String SignName;

//    @VisibleForTesting
//    public TwilioSmsSender(String baseUri, TwilioConfiguration twilioConfiguration, AliYunConfiguration aliYunConfiguration) {
//        Executor executor = ExecutorUtils.newFixedThreadBoundedQueueExecutor(10, 100);
//
//        this.accountId = twilioConfiguration.getAccountId();
//        this.accountToken = twilioConfiguration.getAccountToken();
//        this.numbers = new ArrayList<>(twilioConfiguration.getNumbers());
//        this.localDomain = twilioConfiguration.getLocalDomain();
//        this.messagingServicesId = twilioConfiguration.getMessagingServicesId();
//        this.random = new Random(System.currentTimeMillis());
//        this.smsUri = URI.create(baseUri + "/2010-04-01/Accounts/" + accountId + "/Messages.json");
//        this.voxUri = URI.create(baseUri + "/2010-04-01/Accounts/" + accountId + "/Calls.json");
//        this.httpClient = FaultTolerantHttpClient.newBuilder()
//                .withCircuitBreaker(twilioConfiguration.getCircuitBreaker())
//                .withRetry(twilioConfiguration.getRetry())
//                .withVersion(HttpClient.Version.HTTP_2)
//                .withConnectTimeout(Duration.ofSeconds(10))
//                .withRedirect(HttpClient.Redirect.NEVER)
//                .withExecutor(executor)
//                .withName("twilio")
//                .build();
//        this.AccessKeyId = aliYunConfiguration.getAccessKeyId();
//        this.AccessKeySecret = aliYunConfiguration.getAccessKeySecret();
//        this.TemplateCode = aliYunConfiguration.getTemplateCode();
//        this.SignName = aliYunConfiguration.getSignName();
//    }

//    public TwilioSmsSender(TwilioConfiguration twilioConfiguration, AliYunConfiguration aliYunConfiguration) {
//        this("https://api.twilio.com", twilioConfiguration, aliYunConfiguration);
//    }

    public TwilioSmsSender(AliYunConfiguration aliYunConfiguration) {
        this.AccessKeyId = aliYunConfiguration.getAccessKeyId();
        this.AccessKeySecret = aliYunConfiguration.getAccessKeySecret();
        this.TemplateCode = aliYunConfiguration.getTemplateCode();
        this.SignName = aliYunConfiguration.getSignName();
    }

    public CompletableFuture<Boolean> deliverSmsVerification(String destination, Optional<String> clientType, String verificationCode) {
        //去掉twillio发送短信
//        Map<String, String> requestParameters = new HashMap<>();
//        requestParameters.put("To", destination);
//
//        logger.info("Your OTP is :" + verificationCode);
//        if (Util.isEmpty(messagingServicesId)) {
//            requestParameters.put("From", getRandom(random, numbers));
//        } else {
//            requestParameters.put("MessagingServiceSid", messagingServicesId);
//        }
//
//        if ("ios".equals(clientType.orElse(null))) {
//            requestParameters.put("Body", String.format(SmsSender.SMS_IOS_VERIFICATION_TEXT, verificationCode, verificationCode));
//        } else if ("android-ng".equals(clientType.orElse(null))) {
//            requestParameters.put("Body", String.format(SmsSender.SMS_ANDROID_NG_VERIFICATION_TEXT, verificationCode));
//        } else {
//            requestParameters.put("Body", String.format(SmsSender.SMS_VERIFICATION_TEXT, verificationCode));
//        }
//
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(smsUri)
//                .POST(FormDataBodyPublisher.of(requestParameters))
//                .header("Content-Type", "application/x-www-form-urlencoded")
//                .header("Authorization", "Basic " + Base64.encodeBytes((accountId + ":" + accountToken).getBytes()))
//                .build();

//        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
//                .thenApply(this::parseResponse)
//                .handle(this::processResponse);

        //发送阿里云短信服务
        this.SendSms(destination, verificationCode);

        smsMeter.mark();

        return new CompletableFuture<>();
    }

    public CompletableFuture<Boolean> deliverVoxVerification(String destination, String verificationCode, Optional<String> locale) throws ClientException {
//        String url = "https://" + localDomain + "/v1/voice/description/" + verificationCode;
//
//        if (locale.isPresent()) {
//            url += "?l=" + locale.get();
//        }
//
//        Map<String, String> requestParameters = new HashMap<>();
//        requestParameters.put("Url", url);
//        requestParameters.put("To", destination);
//        requestParameters.put("From", getRandom(random, numbers));
//
//        HttpRequest request = HttpRequest.newBuilder()
//                .uri(voxUri)
//                .POST(FormDataBodyPublisher.of(requestParameters))
//                .header("Content-Type", "application/x-www-form-urlencoded")
//                .header("Authorization", "Basic " + Base64.encodeBytes((accountId + ":" + accountToken).getBytes()))
//                .build();

        voxMeter.mark();

        //发送阿里云语音服务
        this.sendvox(destination, verificationCode);
        return new CompletableFuture<>();
//        return httpClient.sendAsync(request, HttpResponse.BodyHandlers.ofString())
//                .thenApply(this::parseResponse)
//                .handle(this::processResponse);
    }

    private String getRandom(Random random, ArrayList<String> elements) {
        return elements.get(random.nextInt(elements.size()));
    }

    private boolean processResponse(TwilioResponse response, Throwable throwable) {
        if (response != null && response.isSuccess()) {
            priceMeter.mark((long) (response.successResponse.price * 1000));
            return true;
        } else if (response != null && response.isFailure()) {
            logger.info("Twilio request failed: " + response.failureResponse.status + ", " + response.failureResponse.message);
            return false;
        } else if (throwable != null) {
            logger.info("Twilio request failed", throwable);
            return false;
        } else {
            logger.warn("No response or throwable!");
            return false;
        }
    }

    private TwilioResponse parseResponse(HttpResponse<String> response) {
        ObjectMapper mapper = SystemMapper.getMapper();

        if (response.statusCode() >= 200 && response.statusCode() < 300) {
            if ("application/json".equals(response.headers().firstValue("Content-Type").orElse(null))) {
                return new TwilioResponse(TwilioResponse.TwilioSuccessResponse.fromBody(mapper, response.body()));
            } else {
                return new TwilioResponse(new TwilioResponse.TwilioSuccessResponse());
            }
        }

        if ("application/json".equals(response.headers().firstValue("Content-Type").orElse(null))) {
            return new TwilioResponse(TwilioResponse.TwilioFailureResponse.fromBody(mapper, response.body()));
        } else {
            return new TwilioResponse(new TwilioResponse.TwilioFailureResponse());
        }
    }

    public static class TwilioResponse {

        private TwilioSuccessResponse successResponse;
        private TwilioFailureResponse failureResponse;

        TwilioResponse(TwilioSuccessResponse successResponse) {
            this.successResponse = successResponse;
        }

        TwilioResponse(TwilioFailureResponse failureResponse) {
            this.failureResponse = failureResponse;
        }

        boolean isSuccess() {
            return successResponse != null;
        }

        boolean isFailure() {
            return failureResponse != null;
        }

        private static class TwilioSuccessResponse {
            @JsonProperty
            private double price;

            static TwilioSuccessResponse fromBody(ObjectMapper mapper, String body) {
                try {
                    return mapper.readValue(body, TwilioSuccessResponse.class);
                } catch (IOException e) {
                    logger.warn("Error parsing twilio success response: " + e);
                    return new TwilioSuccessResponse();
                }
            }
        }

        private static class TwilioFailureResponse {
            @JsonProperty
            private int status;

            @JsonProperty
            private String message;

            static TwilioFailureResponse fromBody(ObjectMapper mapper, String body) {
                try {
                    return mapper.readValue(body, TwilioFailureResponse.class);
                } catch (IOException e) {
                    logger.warn("Error parsing twilio success response: " + e);
                    return new TwilioFailureResponse();
                }
            }
        }
    }

    /**
     * 发送验证码
     *
     * @param mobile
     * @param code
     */
    public void SendSms(String mobile, String code) {
        try {
            DefaultProfile profile = DefaultProfile.getProfile("default", this.AccessKeyId, this.AccessKeySecret);
            IAcsClient client = new DefaultAcsClient(profile);

            CommonRequest request = new CommonRequest();
            request.setMethod(MethodType.POST);
            request.setDomain("dysmsapi.aliyuncs.com");
            request.setVersion("2017-05-25");
            request.setAction("SendSms");
            //设置超时时间-可自行调整
            System.setProperty("sun.net.client.defaultConnectTimeout", "60000");
            System.setProperty("sun.net.client.defaultReadTimeout", "60000");
            request.putQueryParameter("PhoneNumbers", mobile);
            request.putQueryParameter("TemplateCode", this.TemplateCode);
            request.putQueryParameter("SignName", this.SignName);
            request.putQueryParameter("TemplateParam", String.format("{'code':'%s'}", code));
            CommonResponse response = client.getCommonResponse(request);
            logger.info("发送给[{}]验证码[{}]",mobile,code);
            System.out.println(response.getData());

        } catch (ClientException e) {
            //ignore
            e.printStackTrace();
        }
    }

    public void sendvox(String mobile, String code) throws ClientException {
        //设置访问超时时间
        System.setProperty("sun.net.client.defaultConnectTimeout", "10000");
        System.setProperty("sun.net.client.defaultReadTimeout", "10000");
        //云通信产品-语音API服务产品名称（产品名固定，无需修改）
        final String product = "Dyvmsapi";
        //产品域名（接口地址固定，无需修改）
        final String domain = "dyvmsapi.aliyuncs.com";
        //AK信息
        final String accessKeyId = "LTAI4G4e9CD6p36at165XbUL";
        final String accessKeySecret = "XSjmb5kGg5a2FINgO3Lv4eHnIHlr26";
        //初始化acsClient 暂时不支持多region
        IClientProfile profile = DefaultProfile.getProfile("cn-hangzhou", accessKeyId, accessKeySecret);
        DefaultProfile.addEndpoint("cn-hangzhou", "cn-hangzhou", product, domain);
        IAcsClient acsClient = new DefaultAcsClient(profile);
        SingleCallByTtsRequest request = new SingleCallByTtsRequest();
        //必填-被叫显号,可在语音控制台中找到所购买的显号
        request.setCalledShowNumber("02560000000");
        //必填-被叫号码
        request.setCalledNumber(mobile);
        //必填-Tts模板ID
        request.setTtsCode("TTS_211785537");
        //可选-当模板中存在变量时需要设置此值
        request.setTtsParam(String.format("{'code':'%s'}", code));
        //可选-音量 取值范围 0--200
        request.setVolume(100);
        //可选-播放次数
        request.setPlayTimes(3);
        //可选-外部扩展字段,此ID将在回执消息中带回给调用方
        request.setOutId("yourOutId");
        //hint 此处可能会抛出异常，注意catch
        SingleCallByTtsResponse singleCallByTtsResponse = acsClient.getAcsResponse(request);
        if (singleCallByTtsResponse.getCode() != null && singleCallByTtsResponse.getCode().equals("OK")) {
            //请求成功
            System.out.println("语音文本外呼---------------");
            System.out.println("RequestId=" + singleCallByTtsResponse.getRequestId());
            System.out.println("Code=" + singleCallByTtsResponse.getCode());
            System.out.println("Message=" + singleCallByTtsResponse.getMessage());
            System.out.println("CallId=" + singleCallByTtsResponse.getCallId());
        }
    }
}
