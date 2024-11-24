package org.springframework.security.boot;

import lombok.Getter;
import lombok.Setter;
import lombok.ToString;
import org.springframework.boot.context.properties.ConfigurationProperties;

@ConfigurationProperties(prefix = SecurityDingTalkProperties.PREFIX)
@Getter
@Setter
@ToString
public class SecurityDingTalkProperties {

	public static final String PREFIX = "spring.security.dingtalk";

	/** Whether Enable DingTalk Authentication. */
	private boolean enabled = false;
	
}
