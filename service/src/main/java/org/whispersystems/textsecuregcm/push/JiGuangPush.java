package org.whispersystems.textsecuregcm.push;


import cn.jpush.api.JPushClient;
import cn.jpush.api.common.resp.APIConnectionException;
import cn.jpush.api.common.resp.APIRequestException;
import cn.jpush.api.push.PushResult;
import cn.jpush.api.push.model.Platform;
import cn.jpush.api.push.model.PushPayload;
import cn.jpush.api.push.model.audience.Audience;
import cn.jpush.api.push.model.notification.Notification;
import com.google.gson.JsonObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.gcm.server.Result;
import org.whispersystems.textsecuregcm.configuration.JpushConfiguration;
import org.whispersystems.textsecuregcm.util.GsonUtil;

import javax.annotation.PostConstruct;
import javax.print.DocFlavor;
import java.util.Arrays;

/**
 * 极光推送
 * 封装第三方api相关
 */
public class JiGuangPush {

    // 极光官网-个人管理中心-appkey
    private String appkey;
    // 极光官网-个人管理中心-点击查看-secret
    private String secret;

    private JPushClient jPushClient;

    public JiGuangPush(JpushConfiguration jpushConfiguration) {
        this.appkey = jpushConfiguration.getAppkey();
        this.secret = jpushConfiguration.getSecret();
        this.jPushClient = new JPushClient(secret, appkey);
    }

    private final Logger logger = LoggerFactory.getLogger(JiGuangPush.class);

    /**
     * 广播 (所有平台，所有设备, 不支持附加信息)
     *
     * @param pushBean 推送内容
     * @return
     */
    public Result pushAll(JPushMessage pushBean) {
        return sendPush(PushPayload.newBuilder()
                .setPlatform(Platform.all())
                .setAudience(Audience.all())
                .setNotification(Notification.alert(pushBean.getAlert()))
                .build(),null);
    }

    /**
     * ios广播
     *
     * @param pushBean 推送内容
     * @return
     */
    public Result pushIos(JPushMessage pushBean) {
        return sendPush(PushPayload.newBuilder()
                .setPlatform(cn.jpush.api.push.model.Platform.ios())
                .setAudience(Audience.all())
                .setNotification(Notification.ios(pushBean.getAlert(), pushBean.getExtras()))
                .build(),null);
    }

    /**
     * ios通过registid推送 (一次推送最多 1000 个)
     *
     * @param pushBean  推送内容
     * @param registids 推送id
     * @return
     */
    public Result pushIos(JPushMessage pushBean, String registids) {
        return sendPush(PushPayload.newBuilder()
                .setPlatform(cn.jpush.api.push.model.Platform.ios())
                .setAudience(Audience.registrationId(registids))
                .setNotification(Notification.ios(pushBean.getAlert(), pushBean.getExtras()))
                .build(),registids);
    }

    /**
     * android广播
     *
     * @param pushBean 推送内容
     * @return
     */
    public Result pushAndroid(JPushMessage pushBean) {
        return sendPush(PushPayload.newBuilder()
                .setPlatform(cn.jpush.api.push.model.Platform.android())
                .setAudience(Audience.all())
                .setNotification(Notification.android(pushBean.getAlert(), pushBean.getTitle(), pushBean.getExtras()))
                .build(),null);
    }

    /**
     * android通过registid推送 (一次推送最多 1000 个)
     *
     * @param pushBean  推送内容
     * @param registids 推送id
     * @return
     */
    public Result pushAndroid(JPushMessage pushBean, String registids) {
        return sendPush(PushPayload.newBuilder()
                .setPlatform(cn.jpush.api.push.model.Platform.android())
                .setAudience(Audience.registrationId(registids))
                .setNotification(Notification.android(pushBean.getAlert(), pushBean.getTitle(), pushBean.getExtras()))
                .build(),registids);
    }

    /**
     * 调用api推送
     *
     * @param pushPayload 推送实体
     * @return
     */
    public Result sendPush(PushPayload pushPayload,String registids) {
        logger.info("发送极光推送请求: {}", pushPayload);
        PushResult result;
        try {
            result = this.jPushClient.sendPush(pushPayload);
            if (result != null && result.isResultOK()) {
                logger.info("极光推送请求成功: {}", result);
                return new Result(registids,String.valueOf(result.getResponseCode()),result.getOriginalContent());
            } else {
                logger.info("极光推送请求失败: {}", result);
                return new Result(registids,String.valueOf(result!= null? result.getResponseCode():500),result.getOriginalContent());
            }
        } catch (APIConnectionException  | APIRequestException e) {
            JsonObject object = (JsonObject) GsonUtil.getObject(e.getMessage(), JsonObject.class);
            String errorCode = String.valueOf(object.getAsJsonObject("error").get("code"));
            String errorMsg = String.valueOf(object.getAsJsonObject("error").get("message"));
            logger.error("极光推送请求异常: ", e.getMessage());
            return new Result(registids,errorCode,errorMsg);
        }

    }
}