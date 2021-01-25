package org.springframework.security.boot.dingtalk.authentication;

import java.util.Objects;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.SpringSecurityMessageSource;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

import com.alibaba.fastjson.JSONObject;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import com.dingtalk.api.response.OapiUserGetResponse;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;

public class DingTalkTmpCodeAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private final DingTalkTemplate dingTalkTemplate;
    
    public DingTalkTmpCodeAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkTemplate dingTalkTemplate) {
        this.userDetailsService = userDetailsService;
        this.dingTalkTemplate = dingTalkTemplate;
    }

	@Override
	public void afterPropertiesSet() throws Exception {
		
	}
    
    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/hiwepy">wandl</a>
     * @param authentication  {@link DingTalkTmpCodeAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
    	DingTalkTmpCodeLoginRequest loginRequest = (DingTalkTmpCodeLoginRequest) authentication.getPrincipal();

		if ( !StringUtils.hasText(loginRequest.getUserid()) && !StringUtils.hasText(loginRequest.getLoginTmpCode())) {
			logger.debug("No loginTmpCode or Code found in request.");
			throw new DingTalkCodeNotFoundException("No loginTmpCode or Code found in request.");
		}
		
		try {

			if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
				logger.debug("Invalid App Key {} .", loginRequest.getKey());
				throw new DingTalkCodeNotFoundException("Invalid App Key.");
			}
			
			String appKey = loginRequest.getKey();
			String appSecret = dingTalkTemplate.getAppSecret(loginRequest.getKey());
			// 获取access_token
			String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
			
			DingTalkTmpCodeAuthenticationToken dingTalkToken = (DingTalkTmpCodeAuthenticationToken) authentication;
			
			if ( !StringUtils.hasText(loginRequest.getUserid()) && StringUtils.hasText(loginRequest.getLoginTmpCode())) {
				
				// 第三方应用钉钉扫码登录：通过临时授权码Code获取用户信息，临时授权码只能使用一次
				OapiSnsGetuserinfoBycodeResponse response = dingTalkTemplate.opsForSns().getUserinfoByTmpCode(loginRequest.getLoginTmpCode(), appKey, appSecret);
				/*{ 
				    "errcode": 0,
				    "errmsg": "ok",
				    "user_info": {
				        "nick": "张三",
				        "openid": "liSii8KCxxxxx",
				        "unionid": "7Huu46kk"
				    }
				}*/
				if(!response.isSuccess()) {
					logger.error(response.getBody());
					throw new DingTalkAuthenticationServiceException(response.getErrmsg());
				}
					
				UserInfo userInfo = response.getUserInfo();
				
				dingTalkToken.setUnionid(userInfo.getUnionid());
				dingTalkToken.setOpenid(userInfo.getOpenid());
				loginRequest.setUnionid(userInfo.getUnionid());
				loginRequest.setOpenid(userInfo.getOpenid());
				
			}

			if(Objects.isNull(loginRequest.getUserInfo()) && !Objects.isNull(loginRequest.getUserid()) ) {
				
				// 根据UserId 获取用户信息
				OapiUserGetResponse userInfoResponse = dingTalkTemplate.opsForAccount().getUserByUserid(loginRequest.getUserid(), accessToken);
				if(!userInfoResponse.isSuccess()) {
					logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
					throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
				}
				
				dingTalkToken.setUserInfo(userInfoResponse);
				
			}

			if(Objects.isNull(loginRequest.getUserInfo()) && !Objects.isNull(loginRequest.getUnionid()) ) {
				
				// 根据unionid获取userid
				OapiUserGetUseridByUnionidResponse unionidResponse = dingTalkTemplate.opsForAccount().getUseridByUnionid(loginRequest.getUnionid(), accessToken);
				if(!unionidResponse.isSuccess()) {
					logger.error(JSONObject.toJSONString(AuthResponse.of(unionidResponse.getErrorCode(), unionidResponse.getErrmsg())));
					throw new DingTalkAuthenticationServiceException(unionidResponse.getErrmsg());
				}
				
				// 根据UserId 获取用户信息
				OapiUserGetResponse userInfoResponse = dingTalkTemplate.opsForAccount().getUserByUserid(unionidResponse.getUserid(), accessToken);
				if(!userInfoResponse.isSuccess()) {
					logger.error(JSONObject.toJSONString(AuthResponse.of(userInfoResponse.getErrorCode(), userInfoResponse.getErrmsg())));
					throw new DingTalkAuthenticationServiceException(userInfoResponse.getErrmsg());
				}
				
				dingTalkToken.setUserInfo(userInfoResponse);
				
			}
			
			UserDetails ud = getUserDetailsService().loadUserDetails(dingTalkToken);
	        
	        // User Status Check
	        getUserDetailsChecker().check(ud);
	        
	        DingTalkTmpCodeAuthenticationToken authenticationToken = null;
	        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
	        	authenticationToken = new DingTalkTmpCodeAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
	        } else {
	        	authenticationToken = new DingTalkTmpCodeAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
			}
	        authenticationToken.setDetails(authentication.getDetails());
	        
	        return authenticationToken;
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		}
    }
    
    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkTmpCodeAuthenticationToken.class.isAssignableFrom(authentication));
    }

	public void setUserDetailsChecker(UserDetailsChecker userDetailsChecker) {
		this.userDetailsChecker = userDetailsChecker;
	}

	public UserDetailsChecker getUserDetailsChecker() {
		return userDetailsChecker;
	}

	public UserDetailsServiceAdapter getUserDetailsService() {
		return userDetailsService;
	}
    
}
