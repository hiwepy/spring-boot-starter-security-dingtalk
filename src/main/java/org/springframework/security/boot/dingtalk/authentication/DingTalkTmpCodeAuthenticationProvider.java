package org.springframework.security.boot.dingtalk.authentication;

import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
import org.springframework.security.boot.SecurityDingTalkProperties;
import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.boot.biz.userdetails.UserDetailsServiceAdapter;
import org.springframework.security.boot.dingtalk.exception.DingTalkAuthenticationServiceException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.core.userdetails.UserDetails;
import org.springframework.security.core.userdetails.UserDetailsChecker;
import org.springframework.util.Assert;
import org.springframework.util.StringUtils;

/**
 * https://open.dingtalk.com/document/orgapp-server/scan-qr-code-to-log-on-to-third-party-websites
 */
public class DingTalkTmpCodeAuthenticationProvider implements AuthenticationProvider, InitializingBean {
	
	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
	private final Logger logger = LoggerFactory.getLogger(getClass());
    private final UserDetailsServiceAdapter userDetailsService;
	private final SecurityDingTalkProperties dingtalkProperties;
	private final DingTalkTemplate dingTalkTemplate;

    public DingTalkTmpCodeAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
    		final DingTalkTemplate dingTalkTemplate,
		    final SecurityDingTalkProperties dingtalkProperties) {
		this.userDetailsService = userDetailsService;
		this.dingTalkTemplate = dingTalkTemplate;
		this.dingtalkProperties = dingtalkProperties;
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

		if (!StringUtils.hasText(loginRequest.getCode())) {
			logger.debug("No Code found in request.");
			throw new DingTalkCodeNotFoundException("No Code found in request.");
		}
		

		if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
			logger.debug("Invalid App Key {} .", loginRequest.getKey());
			throw new DingTalkCodeNotFoundException("Invalid App Key.");
		}

		DingTalkTmpCodeAuthenticationToken dingTalkToken = (DingTalkTmpCodeAuthenticationToken) authentication;
		try {
			if (StringUtils.hasText(loginRequest.getCode())) {

				String appKey = loginRequest.getKey();
				String appSecret = dingTalkTemplate.getAppSecret(loginRequest.getCorpId(), loginRequest.getKey());
				// 获取access_token
				String accessToken = dingTalkTemplate.getAccessToken(appKey, appSecret);
				loginRequest.setAccessToken(accessToken);
			}
		} catch (ApiException e) {
			throw new DingTalkAuthenticationServiceException(e.getErrMsg(), e);
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
