/*
 * Copyright (c) 2018, hiwepy (https://github.com/hiwepy).
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 */
package org.springframework.security.boot.dingtalk.authentication;

import java.io.IOException;

import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.exception.AuthenticationMethodNotSupportedException;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.authentication.AbstractAuthenticationProcessingFilter;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import com.fasterxml.jackson.databind.ObjectMapper;

/**
 *  企业内部应用免登：https://open.dingtalk.com/document/orgapp-server/enterprise-internal-application-logon-free
 *  第三方企业应用免登： https://open.dingtalk.com/document/orgapp-server/third-party-enterprise-application-logon-free
 *  应用管理后台免登: https://open.dingtalk.com/document/orgapp-server/log-on-site-application-management-backend
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
public class DingTalkTmpCodeAuthenticationProcessingFilter extends AbstractAuthenticationProcessingFilter {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
    public static final String SPRING_SECURITY_FORM_CROPID_KEY = "cropId";
	public static final String SPRING_SECURITY_FORM_APP_KEY = "key";
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "code";

	private String cropIdParameter = SPRING_SECURITY_FORM_CROPID_KEY;
    private String keyParameter = SPRING_SECURITY_FORM_APP_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;
    private String codeParameter = SPRING_SECURITY_FORM_CODE_KEY;

    private boolean postOnly = false;
    private ObjectMapper objectMapper = new ObjectMapper();
    
    public DingTalkTmpCodeAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/dingtalk/tmpcode"));
		this.objectMapper = objectMapper;
	}
	
	public DingTalkTmpCodeAuthenticationProcessingFilter(ObjectMapper objectMapper, AntPathRequestMatcher requestMatcher) {
		super(requestMatcher);
		this.objectMapper = objectMapper;
	}

    @Override
    public Authentication attemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {

        if (isPostOnly() && !WebUtils.isPostRequest(request) ) {
			if (logger.isDebugEnabled()) {
				logger.debug("Authentication method not supported. Request method: " + request.getMethod());
			}
			throw new AuthenticationMethodNotSupportedException(messages.getMessage(AuthResponseCode.SC_AUTHC_METHOD_NOT_ALLOWED.getMsgKey(), new Object[] { request.getMethod() }, 
					"Authentication method not supported. Request method:" + request.getMethod()));
		}
        
        AbstractAuthenticationToken authRequest;
        
        // Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Post && JSON");
			}
			
			DingTalkTmpCodeLoginRequest loginRequest = objectMapper.readValue(request.getReader(), DingTalkTmpCodeLoginRequest.class);
			
			if ( !StringUtils.hasText(loginRequest.getKey())) {
				logger.debug("No key (appId or appKey) found in request.");
				throw new DingTalkCodeNotFoundException("No key (appId or appKey) found in request.");
			}
			if (!StringUtils.hasText(loginRequest.getCode())) {
				logger.debug("No Code found in request.");
				throw new DingTalkCodeNotFoundException("No Code found in request.");
			}
			
			authRequest = this.authenticationToken( loginRequest );
			
		} else {

			String corpId = obtainCropId(request);
			String appId = obtainKey(request);
			String token = obtainToken(request);
			String code = obtainCode(request);
	        
			if ( !StringUtils.hasText(appId)) {
				logger.debug("No appId found in request.");
				throw new DingTalkCodeNotFoundException("No appId found in request.");
			}
			if ( !StringUtils.hasText(code)) {
				logger.debug("No Code found in request.");
				throw new DingTalkCodeNotFoundException("No Code found in request.");
			}

			DingTalkTmpCodeLoginRequest loginRequest = new DingTalkTmpCodeLoginRequest(corpId, appId, token, code);
	        
	        authRequest = this.authenticationToken( loginRequest);
	        
		}
        

		// Allow subclasses to set the "details" property
		setDetails(request, authRequest);

		return this.getAuthenticationManager().authenticate(authRequest);

    }

	protected String obtainCropId(HttpServletRequest request) {
		return request.getParameter(cropIdParameter);
	}

    protected String obtainKey(HttpServletRequest request) {
        return request.getParameter(keyParameter);
    }

	protected String obtainToken(HttpServletRequest request) {
		return request.getParameter(tokenParameter);
	}

    protected String obtainCode(HttpServletRequest request) {
        return request.getParameter(codeParameter);
    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	protected void setDetails(HttpServletRequest request,
			AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected AbstractAuthenticationToken authenticationToken(DingTalkTmpCodeLoginRequest loginRequest) {
		return new DingTalkTmpCodeAuthenticationToken(loginRequest);
	}

	public String getCropIdParameter() {
		return cropIdParameter;
	}

	public void setCropIdParameter(String cropIdParameter) {
		this.cropIdParameter = cropIdParameter;
	}

	public String getKeyParameter() {
		return keyParameter;
	}

	public void setKeyParameter(String keyParameter) {
		this.keyParameter = keyParameter;
	}

	public void setTokenParameter(String tokenParameter) {
		this.tokenParameter = tokenParameter;
	}

	public String getTokenParameter() {
		return tokenParameter;
	}

	public String getCodeParameter() {
		return codeParameter;
	}

	public void setCodeParameter(String codeParameter) {
		this.codeParameter = codeParameter;
	}

	public boolean isPostOnly() {
		return postOnly;
	}

	public void setPostOnly(boolean postOnly) {
		this.postOnly = postOnly;
	}

}