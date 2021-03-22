package org.whispersystems.textsecuregcm.push;

import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.gcm.server.Message;
import org.whispersystems.gcm.server.Result;
import org.whispersystems.gcm.server.Sender;
import org.whispersystems.textsecuregcm.configuration.JpushConfiguration;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.util.CircuitBreakerUtil;
import org.whispersystems.textsecuregcm.util.Constants;
import org.whispersystems.textsecuregcm.util.SystemMapper;
import org.whispersystems.textsecuregcm.util.Util;

import java.util.HashMap;
import java.util.Map;
import java.util.Optional;
import java.util.concurrent.CompletableFuture;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import static com.codahale.metrics.MetricRegistry.name;
import io.dropwizard.lifecycle.Managed;

public class GCMSender implements Managed {

  private final Logger logger = LoggerFactory.getLogger(GCMSender.class);

  private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
  private final Meter          success        = metricRegistry.meter(name(getClass(), "sent", "success"));
  private final Meter          failure        = metricRegistry.meter(name(getClass(), "sent", "failure"));
  private final Meter          unregistered   = metricRegistry.meter(name(getClass(), "sent", "unregistered"));
  private final Meter          canonical      = metricRegistry.meter(name(getClass(), "sent", "canonical"));

  private final Map<String, Meter> outboundMeters = new HashMap<>() {{
    put("receipt", metricRegistry.meter(name(getClass(), "outbound", "receipt")));
    put("notification", metricRegistry.meter(name(getClass(), "outbound", "notification")));
    put("challenge", metricRegistry.meter(name(getClass(), "outbound", "challenge")));
  }};

  private final AccountsManager   accountsManager;
  private final Sender            signalSender;
  private       ExecutorService   executor;
  private       JiGuangPush       jiGuangPush;


  public GCMSender( AccountsManager accountsManager, String signalKey, JiGuangPush jiGuangPush){
    this.accountsManager = accountsManager;
    this.signalSender    = new Sender(signalKey, SystemMapper.getMapper(), 6);
    CircuitBreakerUtil.registerMetrics(metricRegistry, signalSender.getRetry(), Sender.class);
    this.jiGuangPush     = jiGuangPush;
  }

  @VisibleForTesting
  public GCMSender(AccountsManager accountsManager, Sender sender, ExecutorService executor, JiGuangPush jiGuangPush) {
    this.accountsManager = accountsManager;
    this.signalSender    = sender;
    this.executor        = executor;
    this.jiGuangPush     = jiGuangPush;
  }

  public void sendMessage(GcmMessage message) {
//    Message.Builder builder = Message.newBuilder()
//                                     .withDestination(message.getGcmId())
//                                     .withPriority("high");

    String key;

    switch (message.getType()) {
      case RECEIPT:      key = "receipt";      break;
      case NOTIFICATION: key = "notification"; break;
      case CHALLENGE:    key = "challenge";    break;
      default:           throw new AssertionError();
    }

//    Message request = builder.withDataPart(key, message.getData().orElse("")).build();

    //新加的极光推送
    Result result = this.jiGuangPush.pushAndroid(new JPushMessage(key, message.getData().orElse("")), message.getGcmId());
    //原gcm推送，现注释掉换成极光推送
//    CompletableFuture<Result> future = signalSender.send(request);
    markOutboundMeter(key);

    switch (Integer.parseInt(result.getMessageId())){
      case 200:
        handleCanonicalRegistrationId(message, result);
        break;
      case 1003:
      case 1008:
      case 1004:
        handleBadRegistration(message);
        break;
      case  10:
      case 500:
        handleGenericError(message,result);
        break;
    }

//    future.handle((result, throwable) -> {
//      if (result != null && message.getType() != GcmMessage.Type.CHALLENGE) {
//        if (result.isUnregistered() || result.isInvalidRegistrationId()) {
//          executor.submit(() -> handleBadRegistration(message));
//        } else if (result.hasCanonicalRegistrationId()) {
//          executor.submit(() -> handleCanonicalRegistrationId(message, result));
//        } else if (!result.isSuccess()) {
//          executor.submit(() -> handleGenericError(message, result));
//        } else {
//          success.mark();
//        }
//      } else {
//        logger.warn("FCM Failed: " + throwable + ", " + throwable.getCause());
//      }

//      return null;
//    });
  }

  @Override
  public void start() {
    executor = Executors.newSingleThreadExecutor();
  }

  @Override
  public void stop() {
    this.executor.shutdown();
  }

    /**
     * 未认证或注册码不合法，移除当前注册失败的设备
     * @param message
     */
  private void handleBadRegistration(GcmMessage message) {
      //根据消息中的设备id和gcmId获取用户
    Optional<Account> account = getAccountForEvent(message);

    if (account.isPresent()) {
      //noinspection OptionalGetWithoutIsPresent
        //获取当前用户设备信息
      Device device = account.get().getDevice(message.getDeviceId()).get();

      //判断当前设置是否被移除
      if (device.getUninstalledFeedbackTimestamp() == 0) {
          //这块的逻辑是移除设备吧？
        device.setUninstalledFeedbackTimestamp(Util.todayInMillis());
        accountsManager.update(account.get());
      }
    }

    unregistered.mark();
  }

    /**
     * 设备注册成功，与当前用户绑定
     * @param message
     * @param result
     */
  private void handleCanonicalRegistrationId(GcmMessage message, Result result) {
    logger.warn(String.format("Actually received 'CanonicalRegistrationId' ::: (canonical=%s), (original=%s)",
                              result.getCanonicalRegistrationId(), message.getGcmId()));

    //根据设备获取用户
    Optional<Account> account = getAccountForEvent(message);

    if (account.isPresent()) {
      //noinspection OptionalGetWithoutIsPresent
      Device device = account.get().getDevice(message.getDeviceId()).get();
      //注册设备
      device.setGcmId(result.getCanonicalRegistrationId());

      accountsManager.update(account.get());
    }

    canonical.mark();
  }

    /**
     * 请求失败
     * @param message
     * @param result
     */
  private void handleGenericError(GcmMessage message, Result result) {
    logger.warn(String.format("Unrecoverable Error ::: (error=%s), (gcm_id=%s), " +
                              "(destination=%s), (device_id=%d)",
                              result.getError(), message.getGcmId(), message.getNumber(),
                              message.getDeviceId()));
    failure.mark();
  }

    /**
     * 根据设备id获取用户
     * @param message
     * @return
     */
  private Optional<Account> getAccountForEvent(GcmMessage message) {
      //根据手机号获取用户信息
    Optional<Account> account = accountsManager.get(message.getNumber());

    if (account.isPresent()) {
        //从用户的多个设备中找到当前的设备是否存在
      Optional<Device> device = account.get().getDevice(message.getDeviceId());

      if (device.isPresent()) {
          //设备id存在则判断设备的gcmId是否与当前设备的gcmId一致
        if (message.getGcmId().equals(device.get().getGcmId())) {

          if (device.get().getPushTimestamp() == 0 || System.currentTimeMillis() > (device.get().getPushTimestamp() + TimeUnit.SECONDS.toMillis(10))) {
            return account;
          }
        }
      }
    }

    return Optional.empty();
  }

  private void markOutboundMeter(String key) {
    Meter meter = outboundMeters.get(key);

    if (meter != null) meter.mark();
    else               logger.warn("Unknown outbound key: " + key);
  }
}
