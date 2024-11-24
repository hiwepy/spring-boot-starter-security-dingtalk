package org.springframework.security.boot.dingtalk.authentication;

import com.dingtalk.spring.boot.DingTalkTemplate;
import com.taobao.api.ApiException;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.InitializingBean;
import org.springframework.security.authentication.AccountStatusUserDetailsChecker;
import org.springframework.security.authentication.AuthenticationProvider;
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

@Slf4j
public class DingTalkMaAuthenticationProvider implements AuthenticationProvider, InitializingBean {

	private UserDetailsChecker userDetailsChecker = new AccountStatusUserDetailsChecker();
    private final UserDetailsServiceAdapter userDetailsService;
    private final DingTalkTemplate dingTalkTemplate;

    public DingTalkMaAuthenticationProvider(final UserDetailsServiceAdapter userDetailsService,
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
     * @param authentication  {@link DingTalkMaAuthenticationToken IdentityCodeAuthenticationToken} 对象
     * @return 认证结果{@link Authentication}对象
     * @throws AuthenticationException  认证失败会抛出异常
     */
    @Override
    public Authentication authenticate(Authentication authentication) throws AuthenticationException {

    	Assert.notNull(authentication, "No authentication data provided");

    	if (log.isDebugEnabled()) {
			log.debug("Processing authentication request : " + authentication);
		}

    	DingTalkMaLoginRequest loginRequest = (DingTalkMaLoginRequest) authentication.getPrincipal();

    	if (!StringUtils.hasText(loginRequest.getAuthCode())) {
			log.debug("No authCode found in request.");
			throw new DingTalkCodeNotFoundException("No authCode found in request.");
		}

		if(!dingTalkTemplate.hasAppKey(loginRequest.getKey())) {
			log.debug("Invalid App Key {} .", loginRequest.getKey());
			throw new DingTalkCodeNotFoundException("Invalid App Key.");
		}

		DingTalkMaAuthenticationToken dingTalkToken = (DingTalkMaAuthenticationToken) authentication;
		try {
			if (StringUtils.hasText(loginRequest.getAuthCode())) {

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

		DingTalkMaAuthenticationToken authenticationToken = null;
		if(SecurityPrincipal.class.isAssignableFrom(ud.getClass())) {
			authenticationToken = new DingTalkMaAuthenticationToken(ud, ud.getPassword(), ud.getAuthorities());
		} else {
			authenticationToken = new DingTalkMaAuthenticationToken(ud.getUsername(), ud.getPassword(), ud.getAuthorities());
		}
		authenticationToken.setDetails(authentication.getDetails());

		return authenticationToken;
    }

    @Override
    public boolean supports(Class<?> authentication) {
        return (DingTalkMaAuthenticationToken.class.isAssignableFrom(authentication));
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
