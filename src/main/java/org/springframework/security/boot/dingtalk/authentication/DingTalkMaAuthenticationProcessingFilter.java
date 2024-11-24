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

import com.fasterxml.jackson.databind.ObjectMapper;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.authentication.PostOnlyAuthenticationProcessingFilter;
import org.springframework.security.boot.dingtalk.exception.DingTalkCodeNotFoundException;
import org.springframework.security.boot.utils.WebUtils;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.AuthenticationException;
import org.springframework.security.web.util.matcher.AntPathRequestMatcher;
import org.springframework.util.StringUtils;

import java.io.IOException;

/**
 * https://open.dingtalk.com/document/orgapp-client/mini-program-free-login
 */
public class DingTalkMaAuthenticationProcessingFilter extends PostOnlyAuthenticationProcessingFilter {

	public static final String SPRING_SECURITY_FORM_CROPID_KEY = "cropId";
    public static final String SPRING_SECURITY_FORM_APP_KEY = "key";
	public static final String SPRING_SECURITY_FORM_TOKEN_KEY = "token";
    public static final String SPRING_SECURITY_FORM_CODE_KEY = "authCode";

	private String cropIdParameter = SPRING_SECURITY_FORM_CROPID_KEY;
    private String keyParameter = SPRING_SECURITY_FORM_APP_KEY;
	private String tokenParameter = SPRING_SECURITY_FORM_TOKEN_KEY;
    private String authCodeParameter = SPRING_SECURITY_FORM_CODE_KEY;
    
    private ObjectMapper objectMapper = new ObjectMapper();
    
    public DingTalkMaAuthenticationProcessingFilter(ObjectMapper objectMapper) {
    	super(new AntPathRequestMatcher("/login/dingtalk/ma"));
		this.objectMapper = objectMapper;
	}
	
	public DingTalkMaAuthenticationProcessingFilter(ObjectMapper objectMapper, AntPathRequestMatcher requestMatcher) {
		super(requestMatcher);
		this.objectMapper = objectMapper;
	}
	
    @Override
    public Authentication doAttemptAuthentication(HttpServletRequest request, HttpServletResponse response)
            throws AuthenticationException, IOException, ServletException {
        
        AbstractAuthenticationToken authRequest;
        
        // Post && JSON
		if(WebUtils.isObjectRequest(request)) {
			
			if (logger.isDebugEnabled()) {
				logger.debug("Post && JSON");
			}
			
			DingTalkMaLoginRequest loginRequest = objectMapper.readValue(request.getReader(), DingTalkMaLoginRequest.class);
			
			if ( !StringUtils.hasText(loginRequest.getKey())) {
				logger.debug("No key (appId or appKey) found in request.");
				throw new DingTalkCodeNotFoundException("No key (appId or appKey) found in request.");
			}
			if ( !StringUtils.hasText(loginRequest.getAuthCode())) {
				logger.debug("No AuthCode found in request.");
				throw new DingTalkCodeNotFoundException("No AuthCode found in request.");
			}
			
			authRequest = this.authenticationToken( loginRequest );
			
		} else {
			
			String corpId = obtainCropId(request);
			String appId = obtainKey(request);
			String token = obtainToken(request);
			String authCode = obtainAuthCode(request);
	        
			if ( !StringUtils.hasText(appId)) {
				logger.debug("No appId found in request.");
				throw new DingTalkCodeNotFoundException("No appId found in request.");
			}
			if ( !StringUtils.hasText(authCode)) {
				logger.debug("No authCode found in request.");
				throw new DingTalkCodeNotFoundException("No authCode found in request.");
			}
	        
			DingTalkMaLoginRequest loginRequest = new DingTalkMaLoginRequest(corpId, appId, token, authCode);
	        
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

    protected String obtainAuthCode(HttpServletRequest request) {
        return request.getParameter(authCodeParameter);
    }

    /**
	 * Provided so that subclasses may configure what is put into the authentication
	 * request's details property.
	 *
	 * @param request that an authentication request is being created for
	 * @param authRequest the authentication request object that should have its details
	 * set
	 */
	@Override
	protected void setDetails(HttpServletRequest request,
							  AbstractAuthenticationToken authRequest) {
		authRequest.setDetails(authenticationDetailsSource.buildDetails(request));
	}
	
	protected AbstractAuthenticationToken authenticationToken(DingTalkMaLoginRequest loginRequest) {
		return new DingTalkMaAuthenticationToken(loginRequest);
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

	public String getAuthCodeParameter() {
		return authCodeParameter;
	}

	public void setAuthCodeParameter(String authCodeParameter) {
		this.authCodeParameter = authCodeParameter;
	}

}