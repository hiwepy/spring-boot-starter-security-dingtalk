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

import com.alibaba.fastjson2.JSON;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.context.support.MessageSourceAccessor;
import org.springframework.http.HttpStatus;
import org.springframework.http.MediaType;
import org.springframework.security.authentication.AbstractAuthenticationToken;
import org.springframework.security.boot.biz.SpringSecurityBizMessageSource;
import org.springframework.security.boot.biz.authentication.nested.MatchedAuthenticationSuccessHandler;
import org.springframework.security.boot.biz.exception.AuthResponse;
import org.springframework.security.boot.biz.exception.AuthResponseCode;
import org.springframework.security.boot.biz.userdetails.JwtPayloadRepository;
import org.springframework.security.boot.biz.userdetails.UserProfilePayload;
import org.springframework.security.boot.utils.SubjectUtils;
import org.springframework.security.core.Authentication;

import java.io.IOException;
import java.nio.charset.StandardCharsets;

public class DingTalkMatchedAuthenticationSuccessJwtHandler implements MatchedAuthenticationSuccessHandler {

	protected MessageSourceAccessor messages = SpringSecurityBizMessageSource.getAccessor();
	private JwtPayloadRepository payloadRepository;
	private boolean checkExpiry = false;

	public DingTalkMatchedAuthenticationSuccessJwtHandler(JwtPayloadRepository payloadRepository) {
		this.setPayloadRepository(payloadRepository);
	}

	@Override
	public boolean supports(Authentication authentication) {
		return SubjectUtils.isAssignableFrom(authentication.getClass(), DingTalkMaAuthenticationToken.class
				, DingTalkScanCodeAuthenticationToken.class, DingTalkTmpCodeAuthenticationToken.class);
	}

	@Override
	public void onAuthenticationSuccess(HttpServletRequest request, HttpServletResponse response,
			Authentication authentication) throws IOException, ServletException {

		// 设置状态码和响应头
		response.setStatus(HttpStatus.OK.value());
		response.setContentType(MediaType.APPLICATION_JSON_VALUE);
		response.setCharacterEncoding(StandardCharsets.UTF_8.name());
		// 国际化后的异常信息
		String message = messages.getMessage(AuthResponseCode.SC_AUTHC_SUCCESS.getMsgKey());
		// 写出JSON
		UserProfilePayload profilePayload = getPayloadRepository().getProfilePayload((AbstractAuthenticationToken) authentication, isCheckExpiry());
		JSON.writeTo(response.getOutputStream(), AuthResponse.success(message, profilePayload));

	}

	public JwtPayloadRepository getPayloadRepository() {
		return payloadRepository;
	}

	public void setPayloadRepository(JwtPayloadRepository payloadRepository) {
		this.payloadRepository = payloadRepository;
	}

	public boolean isCheckExpiry() {
		return checkExpiry;
	}

	public void setCheckExpiry(boolean checkExpiry) {
		this.checkExpiry = checkExpiry;
	}
}
