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
package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;
import org.springframework.boot.context.properties.NestedConfigurationProperty;
import org.springframework.security.boot.biz.property.SecurityAuthcProperties;
import org.springframework.security.boot.biz.property.SecurityLogoutProperties;
import org.springframework.security.boot.dingtalk.authentication.DingTalkScanCodeAuthenticationProcessingFilter;

@ConfigurationProperties(SecurityDingTalkScanCodeAuthcProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityDingTalkScanCodeAuthcProperties extends SecurityAuthcProperties {

	public static final String PREFIX = "spring.security.dingtalk.scancode.authc";
	
	/** Authorization Path Pattern */
	private String pathPattern = "/login/dingtalk/scancode";

	private String tokenParameter = DingTalkScanCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TOKEN_KEY;

    /** the code parameter name. Defaults to "loginTmpCode". */
    private String tmpCodeParameter = DingTalkScanCodeAuthenticationProcessingFilter.SPRING_SECURITY_FORM_TMPCODE_KEY;

	@NestedConfigurationProperty
	private SecurityLogoutProperties logout = new SecurityLogoutProperties();
	
}
