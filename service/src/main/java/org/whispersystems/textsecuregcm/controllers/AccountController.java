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
package org.whispersystems.textsecuregcm.controllers;

import com.aliyuncs.exceptions.ClientException;
import com.codahale.metrics.Meter;
import com.codahale.metrics.MetricRegistry;
import com.codahale.metrics.SharedMetricRegistries;
import com.codahale.metrics.annotation.Timed;
import com.google.common.annotations.VisibleForTesting;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.whispersystems.textsecuregcm.auth.AuthenticationCredentials;
import org.whispersystems.textsecuregcm.auth.AuthorizationHeader;
import org.whispersystems.textsecuregcm.auth.DisabledPermittedAccount;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentialGenerator;
import org.whispersystems.textsecuregcm.auth.ExternalServiceCredentials;
import org.whispersystems.textsecuregcm.auth.InvalidAuthorizationHeaderException;
import org.whispersystems.textsecuregcm.auth.StoredRegistrationLock;
import org.whispersystems.textsecuregcm.auth.StoredVerificationCode;
import org.whispersystems.textsecuregcm.auth.TurnToken;
import org.whispersystems.textsecuregcm.auth.TurnTokenGenerator;
import org.whispersystems.textsecuregcm.entities.AccountAttributes;
import org.whispersystems.textsecuregcm.entities.AccountCreationResult;
import org.whispersystems.textsecuregcm.entities.ApnRegistrationId;
import org.whispersystems.textsecuregcm.entities.DeprecatedPin;
import org.whispersystems.textsecuregcm.entities.DeviceName;
import org.whispersystems.textsecuregcm.entities.GcmRegistrationId;
import org.whispersystems.textsecuregcm.entities.RegistrationLock;
import org.whispersystems.textsecuregcm.entities.RegistrationLockFailure;
import org.whispersystems.textsecuregcm.limits.RateLimiters;
import org.whispersystems.textsecuregcm.push.*;
import org.whispersystems.textsecuregcm.recaptcha.RecaptchaClient;
import org.whispersystems.textsecuregcm.sms.SmsSender;
import org.whispersystems.textsecuregcm.sqs.DirectoryQueue;
import org.whispersystems.textsecuregcm.storage.AbusiveHostRule;
import org.whispersystems.textsecuregcm.storage.AbusiveHostRules;
import org.whispersystems.textsecuregcm.storage.Account;
import org.whispersystems.textsecuregcm.storage.AccountsManager;
import org.whispersystems.textsecuregcm.storage.Device;
import org.whispersystems.textsecuregcm.storage.MessagesManager;
import org.whispersystems.textsecuregcm.storage.PendingAccountsManager;
import org.whispersystems.textsecuregcm.storage.UsernamesManager;
import org.whispersystems.textsecuregcm.util.Constants;
import org.whispersystems.textsecuregcm.util.Hex;
import org.whispersystems.textsecuregcm.util.Util;
import org.whispersystems.textsecuregcm.util.VerificationCode;

import javax.validation.Valid;
import javax.ws.rs.Consumes;
import javax.ws.rs.DELETE;
import javax.ws.rs.GET;
import javax.ws.rs.HeaderParam;
import javax.ws.rs.PUT;
import javax.ws.rs.Path;
import javax.ws.rs.PathParam;
import javax.ws.rs.Produces;
import javax.ws.rs.QueryParam;
import javax.ws.rs.WebApplicationException;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.List;
import java.util.Map;
import java.util.Optional;
import java.util.UUID;

import static com.codahale.metrics.MetricRegistry.name;

import io.dropwizard.auth.Auth;

@SuppressWarnings("OptionalUsedAsFieldOrParameterType")
@Path("/v1/accounts")
public class AccountController {

    private final Logger logger = LoggerFactory.getLogger(AccountController.class);
    private final MetricRegistry metricRegistry = SharedMetricRegistries.getOrCreate(Constants.METRICS_NAME);
    private final Meter newUserMeter = metricRegistry.meter(name(AccountController.class, "brand_new_user"));
    private final Meter blockedHostMeter = metricRegistry.meter(name(AccountController.class, "blocked_host"));
    private final Meter filteredHostMeter = metricRegistry.meter(name(AccountController.class, "filtered_host"));
    private final Meter rateLimitedHostMeter = metricRegistry.meter(name(AccountController.class, "rate_limited_host"));
    private final Meter rateLimitedPrefixMeter = metricRegistry.meter(name(AccountController.class, "rate_limited_prefix"));
    private final Meter captchaSuccessMeter = metricRegistry.meter(name(AccountController.class, "captcha_success"));
    private final Meter captchaFailureMeter = metricRegistry.meter(name(AccountController.class, "captcha_failure"));


    private final PendingAccountsManager pendingAccounts;
    private final AccountsManager accounts;
    private final UsernamesManager usernames;
    private final AbusiveHostRules abusiveHostRules;
    private final RateLimiters rateLimiters;
    private final SmsSender smsSender;
    private final DirectoryQueue directoryQueue;
    private final MessagesManager messagesManager;
    private final TurnTokenGenerator turnTokenGenerator;
    private final Map<String, Integer> testDevices;
    private final RecaptchaClient recaptchaClient;
    private final GCMSender gcmSender;
    private final APNSender apnSender;
    private final ExternalServiceCredentialGenerator backupServiceCredentialGenerator;

    public AccountController(PendingAccountsManager pendingAccounts,
                             AccountsManager accounts,
                             UsernamesManager usernames,
                             AbusiveHostRules abusiveHostRules,
                             RateLimiters rateLimiters,
                             SmsSender smsSenderFactory,
                             DirectoryQueue directoryQueue,
                             MessagesManager messagesManager,
                             TurnTokenGenerator turnTokenGenerator,
                             Map<String, Integer> testDevices,
                             RecaptchaClient recaptchaClient,
                             GCMSender gcmSender,
                             APNSender apnSender,
                             ExternalServiceCredentialGenerator backupServiceCredentialGenerator) {
        this.pendingAccounts = pendingAccounts;
        this.accounts = accounts;
        this.usernames = usernames;
        this.abusiveHostRules = abusiveHostRules;
        this.rateLimiters = rateLimiters;
        this.smsSender = smsSenderFactory;
        this.directoryQueue = directoryQueue;
        this.messagesManager = messagesManager;
        this.testDevices = testDevices;
        this.turnTokenGenerator = turnTokenGenerator;
        this.recaptchaClient = recaptchaClient;
        this.gcmSender = gcmSender;
        this.apnSender = apnSender;
        this.backupServiceCredentialGenerator = backupServiceCredentialGenerator;
    }

    /**
     * 验证当前设备注册码是否符合规范
     * 如否，则移除当前设备
     * 如是，则注册码与当前用户绑定
     *
     * @param pushType   设备类型 Android(fcm) or IOS(apn)
     * @param pushToken  注册码 （极光id）
     * @param number     手机号
     */
    @Timed  //metrics
    @GET
    @Path("/{type}/preauth/{token}/{number}")
    public Response getPreAuth(@PathParam("type") String pushType,
                               @PathParam("token") String pushToken,
                               @PathParam("number") String number) {
        //判断设备类型是Android or IOS or return 400
        if (!"apn".equals(pushType) && !"fcm".equals(pushType)) {
            return Response.status(400).build();
        }

        //判断number是否符合手机号规范
//        if (!Util.isValidNumber(number)) {
//            return Response.status(400).build();
//        }

        //生成一个16位密码学安全随机数----pushcode
        String pushChallenge = generatePushChallenge();
        //校验码实体类  验证码，时间戳，pushcode
        StoredVerificationCode storedVerificationCode = new StoredVerificationCode(null,
                System.currentTimeMillis(),
                pushChallenge);

        //存储redis和postgresql
        pendingAccounts.store(number, storedVerificationCode);

        //推送消息，验证当前设备是否合法注册
        if ("fcm".equals(pushType)) {
            gcmSender.sendMessage(new GcmMessage(pushToken, number, 0, GcmMessage.Type.CHALLENGE, Optional.of(storedVerificationCode.getPushCode())));
        } else if ("apn".equals(pushType)) {
            apnSender.sendMessage(new ApnMessage(pushToken, number, 0, true, Optional.of(storedVerificationCode.getPushCode())));
        } else {
            throw new AssertionError();
        }

        return Response.ok().build();
    }

    /**
     * 创建账号
     * @param transport      短信类型：sms|voice
     * @param number         手机号
     * @param forwardedFor   重定向：貌似没啥用
     * @param locale         语言：调用twillio语音验证码需要
     * @param client         设备类型：调用twillio需要（Android or IOS）
     * @param captcha        人机校验验证码：去掉
     * @param pushChallenge  pushcode？？？哪里来的
     * @return
     * @throws RateLimitExceededException
     * @throws ClientException
     */
    @Timed
    @GET
    @Path("/{transport}/code/{number}")
    public Response createAccount(@PathParam("transport") String transport,
                                  @PathParam("number") String number,
                                  @HeaderParam("X-Forwarded-For") String forwardedFor,
                                  @HeaderParam("Accept-Language") Optional<String> locale,
                                  @QueryParam("client") Optional<String> client,
                                  @QueryParam("captcha") Optional<String> captcha,
                                  @QueryParam("challenge") Optional<String> pushChallenge)
            throws RateLimitExceededException, ClientException {
        //校验手机号规则是否合法
//        if (!Util.isValidNumber(number)) {
//            logger.info("Invalid number: " + number);
//            throw new WebApplicationException(Response.status(400).build());
//        }

        //forwardedFor不知道干嘛，忽略
//        String requester = Arrays.stream(forwardedFor.split(","))
//                .map(String::trim)
//                .reduce((a, b) -> b)
//                .orElseThrow();

        //根据手机号获取校验码，getPreAuth方法保存过
        Optional<StoredVerificationCode> storedChallenge = pendingAccounts.getCodeForNumber(number);
        //各种校验，可忽略
//        CaptchaRequirement requirement = requiresCaptcha(number, transport, forwardedFor, requester, captcha, storedChallenge, pushChallenge);

        //谷歌人机认证校验码？ 去掉
//        if (requirement.isCaptchaRequired()) {
//            if (requirement.isAutoBlock() && shouldAutoBlock(requester)) {
//                logger.info("Auto-block: " + requester);
//                abusiveHostRules.setBlockedHost(requester, "Auto-Block");
//            }
//
//            return Response.status(402).build();
//        }

        //判断是sms or voice，校验规则，暂时保留不动，去掉怕出问题
        switch (transport) {
            case "sms":
                rateLimiters.getSmsDestinationLimiter().validate(number);
                break;
            case "voice":
                rateLimiters.getVoiceDestinationLimiter().validate(number);
                rateLimiters.getVoiceDestinationDailyLimiter().validate(number);
                break;
            default:
                throw new WebApplicationException(Response.status(422).build());
        }

        //获取了新的校验码
        VerificationCode verificationCode = generateVerificationCode(number);
        //保存新的校验码
        StoredVerificationCode storedVerificationCode = new StoredVerificationCode(verificationCode.getVerificationCode(),
                System.currentTimeMillis(),
                storedChallenge.map(StoredVerificationCode::getPushCode).orElse(null));

        //存储新的校验码
        pendingAccounts.store(number, storedVerificationCode);

        //发送sms or voice，已改成阿里云
        if (testDevices.containsKey(number)) {
            // noop
        } else if (transport.equals("sms")) {
            smsSender.deliverSmsVerification(number, client, verificationCode.getVerificationCodeDisplay());
        } else if (transport.equals("voice")) {
            smsSender.deliverVoxVerification(number, verificationCode.getVerificationCode(), locale);
        }

        metricRegistry.meter(name(AccountController.class, "create", Util.getCountryCode(number))).mark();

        return Response.ok().build();
    }

    /**
     * 校验账户
     * @param verificationCode        校验码
     * @param authorizationHeader     权限认证header：获取用户信息
     * @param userAgent               用户设备
     * @param accountAttributes       用户属性
     * @return
     * @throws RateLimitExceededException
     */
    @Timed
    @PUT
    @Consumes(MediaType.APPLICATION_JSON)
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/code/{verification_code}")
    public AccountCreationResult verifyAccount(@PathParam("verification_code") String verificationCode,
                                               @HeaderParam("Authorization") String authorizationHeader,
                                               @HeaderParam("X-Signal-Agent") String userAgent,
                                               @Valid AccountAttributes accountAttributes)
            throws RateLimitExceededException {
        try {
            //认证，认证成功则获取用户信息
            AuthorizationHeader header = AuthorizationHeader.fromFullHeader(authorizationHeader);
            String number = header.getIdentifier().getNumber();
            String password = header.getPassword();

            if (number == null) {
                throw new WebApplicationException(400);
            }

            rateLimiters.getVerifyLimiter().validate(number);

            //根据手机号获取校验码
            Optional<StoredVerificationCode> storedVerificationCode = pendingAccounts.getCodeForNumber(number);

            //判断校验码是否合法
            if (storedVerificationCode.isEmpty() || !storedVerificationCode.get().isValid(verificationCode)) {
                throw new WebApplicationException(Response.status(403).build());
            }

            //根据手机号获取账号
            Optional<Account> existingAccount = accounts.get(number);

            //貌似是一堆校验，确认手机号是否可以注册？？？
            //这串走完是创建账号了
            Optional<StoredRegistrationLock> existingRegistrationLock = existingAccount.map(Account::getRegistrationLock);
            Optional<ExternalServiceCredentials> existingBackupCredentials = existingAccount.map(Account::getUuid)
                    .map(uuid -> backupServiceCredentialGenerator.generateFor(uuid.toString()));

            if (existingRegistrationLock.isPresent() && existingRegistrationLock.get().requiresClientRegistrationLock()) {
                rateLimiters.getVerifyLimiter().clear(number);

                if (!Util.isEmpty(accountAttributes.getRegistrationLock()) || !Util.isEmpty(accountAttributes.getPin())) {
                    rateLimiters.getPinLimiter().validate(number);
                }

                if (!existingRegistrationLock.get().verify(accountAttributes.getRegistrationLock(), accountAttributes.getPin())) {
                    throw new WebApplicationException(Response.status(423)
                            .entity(new RegistrationLockFailure(existingRegistrationLock.get().getTimeRemaining(),
                                    existingRegistrationLock.get().needsFailureCredentials() ? existingBackupCredentials.orElseThrow() : null))
                            .build());
                }

                rateLimiters.getPinLimiter().clear(number);
            }

            //创建账号
            Account account = createAccount(number, password, userAgent, accountAttributes);

            metricRegistry.meter(name(AccountController.class, "verify", Util.getCountryCode(number))).mark();

            //返回用户uuid，是否允许存储
            return new AccountCreationResult(account.getUuid(), existingAccount.map(Account::isStorageSupported).orElse(false));
        } catch (InvalidAuthorizationHeaderException e) {
            logger.info("Bad Authorization Header", e);
            throw new WebApplicationException(Response.status(401).build());
        }
    }

    /**
     * 获取turn的tooken
     * @param account     用户信息
     * @return
     * @throws RateLimitExceededException
     */
    @Timed
    @GET
    @Path("/turn/")
    @Produces(MediaType.APPLICATION_JSON)
    public TurnToken getTurnToken(@Auth Account account) throws RateLimitExceededException {
        rateLimiters.getTurnLimiter().validate(account.getNumber());
        return turnTokenGenerator.generate();
    }

    /**
     * 设置gcm注册id
     * @param disabledPermittedAccount
     * @param registrationId
     */
    @Timed
    @PUT
    @Path("/gcm/")
    @Consumes(MediaType.APPLICATION_JSON)
    public void setGcmRegistrationId(@Auth DisabledPermittedAccount disabledPermittedAccount, @Valid GcmRegistrationId registrationId) {
        Account account = disabledPermittedAccount.getAccount();
        Device device = account.getAuthenticatedDevice().get();
        boolean wasAccountEnabled = account.isEnabled();

        if (device.getGcmId() != null &&
                device.getGcmId().equals(registrationId.getGcmRegistrationId())) {
            return;
        }

        device.setApnId(null);
        device.setVoipApnId(null);
        device.setGcmId(registrationId.getGcmRegistrationId());
        device.setFetchesMessages(false);

        accounts.update(account);

        if (!wasAccountEnabled && account.isEnabled()) {
            directoryQueue.addRegisteredUser(account.getUuid(), account.getNumber());
        }
    }


    @Timed
    @DELETE
    @Path("/gcm/")
    public void deleteGcmRegistrationId(@Auth DisabledPermittedAccount disabledPermittedAccount) {
        Account account = disabledPermittedAccount.getAccount();
        Device device = account.getAuthenticatedDevice().get();
        device.setGcmId(null);
        device.setFetchesMessages(false);

        accounts.update(account);

        if (!account.isEnabled()) {
            directoryQueue.deleteRegisteredUser(account.getUuid(), account.getNumber());
        }
    }

    @Timed
    @PUT
    @Path("/apn/")
    @Consumes(MediaType.APPLICATION_JSON)
    public void setApnRegistrationId(@Auth DisabledPermittedAccount disabledPermittedAccount, @Valid ApnRegistrationId registrationId) {
        Account account = disabledPermittedAccount.getAccount();
        Device device = account.getAuthenticatedDevice().get();
        boolean wasAccountEnabled = account.isEnabled();

        device.setApnId(registrationId.getApnRegistrationId());
        device.setVoipApnId(registrationId.getVoipRegistrationId());
        device.setGcmId(null);
        device.setFetchesMessages(false);
        accounts.update(account);

        if (!wasAccountEnabled && account.isEnabled()) {
            directoryQueue.addRegisteredUser(account.getUuid(), account.getNumber());
        }
    }

    @Timed
    @DELETE
    @Path("/apn/")
    public void deleteApnRegistrationId(@Auth DisabledPermittedAccount disabledPermittedAccount) {
        Account account = disabledPermittedAccount.getAccount();
        Device device = account.getAuthenticatedDevice().get();
        device.setApnId(null);
        device.setFetchesMessages(false);

        accounts.update(account);

        if (!account.isEnabled()) {
            directoryQueue.deleteRegisteredUser(account.getUuid(), account.getNumber());
        }
    }

    @Timed
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/registration_lock")
    public void setRegistrationLock(@Auth Account account, @Valid RegistrationLock accountLock) {
        AuthenticationCredentials credentials = new AuthenticationCredentials(accountLock.getRegistrationLock());
        account.setRegistrationLock(credentials.getHashedAuthenticationToken(), credentials.getSalt());
        account.setPin(null);

        accounts.update(account);
    }

    @Timed
    @DELETE
    @Path("/registration_lock")
    public void removeRegistrationLock(@Auth Account account) {
        account.setRegistrationLock(null, null);
        accounts.update(account);
    }

    @Timed
    @PUT
    @Produces(MediaType.APPLICATION_JSON)
    @Path("/pin/")
    public void setPin(@Auth Account account, @Valid DeprecatedPin accountLock) {
        account.setPin(accountLock.getPin());
        account.setRegistrationLock(null, null);

        accounts.update(account);
    }

    @Timed
    @DELETE
    @Path("/pin/")
    public void removePin(@Auth Account account) {
        account.setPin(null);
        accounts.update(account);
    }

    @Timed
    @PUT
    @Path("/name/")
    public void setName(@Auth DisabledPermittedAccount disabledPermittedAccount, @Valid DeviceName deviceName) {
        Account account = disabledPermittedAccount.getAccount();
        account.getAuthenticatedDevice().get().setName(deviceName.getDeviceName());
        accounts.update(account);
    }

    @Timed
    @DELETE
    @Path("/signaling_key")
    public void removeSignalingKey(@Auth DisabledPermittedAccount disabledPermittedAccount) {
        Account account = disabledPermittedAccount.getAccount();
        account.getAuthenticatedDevice().get().setSignalingKey(null);
        accounts.update(account);
    }

    @Timed
    @PUT
    @Path("/attributes/")
    @Consumes(MediaType.APPLICATION_JSON)
    public void setAccountAttributes(@Auth DisabledPermittedAccount disabledPermittedAccount,
                                     @HeaderParam("X-Signal-Agent") String userAgent,
                                     @Valid AccountAttributes attributes) {
        Account account = disabledPermittedAccount.getAccount();
        Device device = account.getAuthenticatedDevice().get();

        device.setFetchesMessages(attributes.getFetchesMessages());
        device.setName(attributes.getName());
        device.setLastSeen(Util.todayInMillis());
        device.setCapabilities(attributes.getCapabilities());
        device.setRegistrationId(attributes.getRegistrationId());
        device.setSignalingKey(attributes.getSignalingKey());
        device.setUserAgent(userAgent);

        setAccountRegistrationLockFromAttributes(account, attributes);

        account.setUnidentifiedAccessKey(attributes.getUnidentifiedAccessKey());
        account.setUnrestrictedUnidentifiedAccess(attributes.isUnrestrictedUnidentifiedAccess());

        accounts.update(account);
    }

    @GET
    @Path("/whoami")
    @Produces(MediaType.APPLICATION_JSON)
    public AccountCreationResult whoAmI(@Auth Account account) {
        return new AccountCreationResult(account.getUuid(), account.isStorageSupported());
    }

    @DELETE
    @Path("/username")
    @Produces(MediaType.APPLICATION_JSON)
    public void deleteUsername(@Auth Account account) {
        usernames.delete(account.getUuid());
    }

    @PUT
    @Path("/username/{username}")
    @Produces(MediaType.APPLICATION_JSON)
    public Response setUsername(@Auth Account account, @PathParam("username") String username) throws RateLimitExceededException {
        rateLimiters.getUsernameSetLimiter().validate(account.getUuid().toString());

        if (username == null || username.isEmpty()) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        username = username.toLowerCase();

        if (!username.matches("^[a-z_][a-z0-9_]+$")) {
            return Response.status(Response.Status.BAD_REQUEST).build();
        }

        if (!usernames.put(account.getUuid(), username)) {
            return Response.status(Response.Status.CONFLICT).build();
        }

        return Response.ok().build();
    }

    private CaptchaRequirement requiresCaptcha(String number, String transport, String forwardedFor,
                                               String requester,
                                               Optional<String> captchaToken,
                                               Optional<StoredVerificationCode> storedVerificationCode,
                                               Optional<String> pushChallenge) {

        //谷歌人机校验，去掉
//        if (captchaToken.isPresent()) {
//            boolean validToken = recaptchaClient.verify(captchaToken.get(), requester);
//
//            if (validToken) {
//                captchaSuccessMeter.mark();
//                return new CaptchaRequirement(false, false);
//            } else {
//                captchaFailureMeter.mark();
//                return new CaptchaRequirement(true, false);
//            }
//        }

        //客户端传的校验码与数据库中原绑定校验码确认是否一致
        //感觉像是确认设备
        //不知客户端传的校验码哪里来的
        if (pushChallenge.isPresent()) {
            Optional<String> storedPushChallenge = storedVerificationCode.map(StoredVerificationCode::getPushCode);

            if (!pushChallenge.get().equals(storedPushChallenge.orElse(null))) {
                return new CaptchaRequirement(true, false);
            }
        }

        //后续不重要，不用twillio发送短信
        List<AbusiveHostRule> abuseRules = abusiveHostRules.getAbusiveHostRulesFor(requester);

        for (AbusiveHostRule abuseRule : abuseRules) {
            if (abuseRule.isBlocked()) {
                logger.info("Blocked host: " + transport + ", " + number + ", " + requester + " (" + forwardedFor + ")");
                blockedHostMeter.mark();
                return new CaptchaRequirement(true, false);
            }

            if (!abuseRule.getRegions().isEmpty()) {
                if (abuseRule.getRegions().stream().noneMatch(number::startsWith)) {
                    logger.info("Restricted host: " + transport + ", " + number + ", " + requester + " (" + forwardedFor + ")");
                    filteredHostMeter.mark();
                    return new CaptchaRequirement(true, false);
                }
            }
        }

        try {
            rateLimiters.getSmsVoiceIpLimiter().validate(requester);
        } catch (RateLimitExceededException e) {
            logger.info("Rate limited exceeded: " + transport + ", " + number + ", " + requester + " (" + forwardedFor + ")");
            rateLimitedHostMeter.mark();
            return new CaptchaRequirement(true, true);
        }

        try {
            rateLimiters.getSmsVoicePrefixLimiter().validate(Util.getNumberPrefix(number));
        } catch (RateLimitExceededException e) {
            logger.info("Prefix rate limit exceeded: " + transport + ", " + number + ", (" + forwardedFor + ")");
            rateLimitedPrefixMeter.mark();
            return new CaptchaRequirement(true, true);
        }

        return new CaptchaRequirement(false, false);
    }

    private boolean shouldAutoBlock(String requester) {
        try {
            rateLimiters.getAutoBlockLimiter().validate(requester);
        } catch (RateLimitExceededException e) {
            return true;
        }

        return false;
    }

    private Account createAccount(String number, String password, String userAgent, AccountAttributes accountAttributes) {
        Device device = new Device();
        device.setId(Device.MASTER_ID);
        device.setAuthenticationCredentials(new AuthenticationCredentials(password));
        device.setSignalingKey(accountAttributes.getSignalingKey());
        device.setFetchesMessages(accountAttributes.getFetchesMessages());
        device.setRegistrationId(accountAttributes.getRegistrationId());
        device.setName(accountAttributes.getName());
        device.setCapabilities(accountAttributes.getCapabilities());
        device.setCreated(System.currentTimeMillis());
        device.setLastSeen(Util.todayInMillis());
        device.setUserAgent(userAgent);

        Account account = new Account();
        account.setNumber(number);
        account.setUuid(UUID.randomUUID());
        account.addDevice(device);
        setAccountRegistrationLockFromAttributes(account, accountAttributes);
        account.setUnidentifiedAccessKey(accountAttributes.getUnidentifiedAccessKey());
        account.setUnrestrictedUnidentifiedAccess(accountAttributes.isUnrestrictedUnidentifiedAccess());

        if (accounts.create(account)) {
            newUserMeter.mark();
        }

        if (account.isEnabled()) {
            directoryQueue.addRegisteredUser(account.getUuid(), number);
        } else {
            directoryQueue.deleteRegisteredUser(account.getUuid(), number);
        }

        messagesManager.clear(number);
        pendingAccounts.remove(number);

        return account;
    }

    private void setAccountRegistrationLockFromAttributes(Account account, @Valid AccountAttributes attributes) {
        if (!Util.isEmpty(attributes.getPin())) {
            account.setPin(attributes.getPin());
        } else if (!Util.isEmpty(attributes.getRegistrationLock())) {
            AuthenticationCredentials credentials = new AuthenticationCredentials(attributes.getRegistrationLock());
            account.setRegistrationLock(credentials.getHashedAuthenticationToken(), credentials.getSalt());
        } else {
            account.setPin(null);
            account.setRegistrationLock(null, null);
        }
    }

    @VisibleForTesting
    protected VerificationCode generateVerificationCode(String number) {
        if (testDevices.containsKey(number)) {
            return new VerificationCode(testDevices.get(number));
        }

        SecureRandom random = new SecureRandom();
        int randomInt = 100000 + random.nextInt(900000);
        return new VerificationCode(randomInt);
    }

    private String generatePushChallenge() {
        SecureRandom random = new SecureRandom();
        byte[] challenge = new byte[16];
        random.nextBytes(challenge);

        return Hex.toStringCondensed(challenge);
    }

    private static class CaptchaRequirement {
        private final boolean captchaRequired;
        private final boolean autoBlock;

        private CaptchaRequirement(boolean captchaRequired, boolean autoBlock) {
            this.captchaRequired = captchaRequired;
            this.autoBlock = autoBlock;
        }

        boolean isCaptchaRequired() {
            return captchaRequired;
        }

        boolean isAutoBlock() {
            return autoBlock;
        }
    }
}
