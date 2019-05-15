package org.springframework.security.boot.dingtalk.authentication;

import java.util.concurrent.ExecutionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.authentication.InternalAuthenticationServiceException;
import org.springframework.security.boot.SecurityDingTalkProperties;
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

import com.dingtalk.api.DefaultDingTalkClient;
import com.dingtalk.api.request.OapiSnsGetuserinfoBycodeRequest;
import com.dingtalk.api.request.OapiUserGetUseridByUnionidRequest;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse;
import com.dingtalk.api.response.OapiSnsGetuserinfoBycodeResponse.UserInfo;
import com.dingtalk.api.response.OapiUserGetUseridByUnionidResponse;
import com.taobao.api.ApiException;

public class DingTalkAuthenticationProvider implements AuthenticationProvider {
	
	protected MessageSourceAccessor messages = SpringSecurityMessageSource.getAccessor();
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
    private final SecurityDingTalkProperties dingtalkProperties;
    private final DingTalkAccessTokenProvider dingTalkAccessTokenProvider;
    // https://open-doc.dingtalk.com/microapp/serverapi2/etaarr#-2
    private final DefaultDingTalkClient bycodeClient;
	// https://open-doc.dingtalk.com/microapp/serverapi2/ege851#-5
    private final DefaultDingTalkClient unionidClient;
	
    public DingTalkAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkAccessTokenProvider dingTalkAccessTokenProvider,
    		final SecurityDingTalkProperties dingtalkProperties) {
        this.userDetailsService = userDetailsService;
        this.dingTalkAccessTokenProvider = dingTalkAccessTokenProvider;
        this.dingtalkProperties = dingtalkProperties;
        this.bycodeClient = new DefaultDingTalkClient(dingtalkProperties.getUserInfoURL());
        this.unionidClient = new DefaultDingTalkClient(dingtalkProperties.getUserIdURL());
    }

    /**
     * 
     * <p>完成匹配Token的认证，这里返回的对象最终会通过：SecurityContextHolder.getContext().setAuthentication(authResult); 放置在上下文中</p>
     * @author 		：<a href="https://github.com/vindell">wandl</a>
     * @param authentication  {@link DingTalkAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {
        
    	Assert.notNull(authentication, "No authentication data provided");
    	
    	if (logger.isDebugEnabled()) {
			logger.debug("Processing authentication request : " + authentication);
		}
 
        String loginTmpCode = (String) authentication.getCredentials();

		if (!StringUtils.hasLength(loginTmpCode)) {
			logger.debug("No loginTmpCode found in request.");
			throw new DingTalkCodeNotFoundException("No loginTmpCode found in request.");
		}
		
		try {
			
			OapiSnsGetuserinfoBycodeRequest bycodeRequest = new OapiSnsGetuserinfoBycodeRequest();
			bycodeRequest.setTmpAuthCode(loginTmpCode);
			OapiSnsGetuserinfoBycodeResponse response = bycodeClient.execute(bycodeRequest, dingtalkProperties.getAccessKey(), dingtalkProperties.getAccessSecret());
			/*{ 
			    "errcode": 0,
			    "errmsg": "ok",
			    "user_info": {
			        "nick": "张三",
			        "openid": "liSii8KCxxxxx",
			        "unionid": "7Huu46kk"
			    }
			}*/
			// 认证成功
			if(response.getErrcode() == 0) {
				
				UserInfo userInfo = response.getUserInfo();
				
				DingTalkAuthenticationToken dingTalkToken = (DingTalkAuthenticationToken) authentication;
				dingTalkToken.setNick(userInfo.getNick());
				dingTalkToken.setOpenid(userInfo.getOpenid());
				dingTalkToken.setUnionid(userInfo.getUnionid());
				
				OapiUserGetUseridByUnionidRequest unionidRequest = new OapiUserGetUseridByUnionidRequest();
				unionidRequest.setUnionid(userInfo.getUnionid());
				unionidRequest.setHttpMethod("GET");
				OapiUserGetUseridByUnionidResponse unionidResponse = unionidClient.execute(unionidRequest, dingTalkAccessTokenProvider.getAccessToken());
				dingTalkToken.setPrincipal(unionidResponse.getUserid());
				
				UserDetails ud = getUserDetailsService().loadUserDetails(dingTalkToken);
		        
		        // User Status Check
		        getUserDetailsChecker().check(ud);
		        
		        DingTalkAuthenticationToken authenticationToken = null;
		        if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
		        	SecurityPrincipal principal = (SecurityPrincipal)ud;
		        	if(!StringUtils.hasText(principal.getAlias())) {
		        		principal.setAlias(userInfo.getNick());
		        	}
		        	authenticationToken = new DingTalkAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());        	
		        } else {
		        	authenticationToken = new DingTalkAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
				}
		        authenticationToken.setDetails(authentication.getDetails());
		        
		        return authenticationToken;
			}
			throw new DingTalkAuthenticationServiceException(response.getErrmsg());
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
		} catch (ExecutionException e) {
			throw new InternalAuthenticationServiceException(e.getMessage(), e);
		}
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkAuthenticationToken.class.isAssignableFrom(authentication));
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
