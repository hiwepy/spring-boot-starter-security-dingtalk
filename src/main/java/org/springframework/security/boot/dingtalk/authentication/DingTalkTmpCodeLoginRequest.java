package org.springframework.security.boot.dingtalk.authentication;

import com.fasterxml.jackson.annotation.JsonCreator;
import com.fasterxml.jackson.annotation.JsonIgnoreProperties;
import com.fasterxml.jackson.annotation.JsonProperty;

/**
 * 企业内部应用免登、第三方企业应用免登、应用管理后台免登
 * @author 		： <a href="https://github.com/hiwepy">wandl</a>
 */
@JsonIgnoreProperties(ignoreUnknown = true)
public class DingTalkTmpCodeLoginRequest {

	/**
	 * 	企业的corpid
	 */
	protected String corpId;
	/**
	 * 	应用的唯一标识key
	 */
	protected String key;
	/**
	 * 临时登录凭证code
	 */
	protected String code;
	/**
	 * 	当前请求使用的token，用于绑定用户
	 */
	protected String token;
	/**
	 * Access Token
	 */
	protected String accessToken;
    
	@JsonIgnoreProperties(ignoreUnknown = true)
    @JsonCreator
    public DingTalkTmpCodeLoginRequest(@JsonProperty("corpId") String corpId,
									   @JsonProperty("key") String key,
									   @JsonProperty("token") String token,
									   @JsonProperty("code") String code) {
        this.corpId = corpId;
		this.key = key;
		this.token = token;
		this.code = code;
    }

	public String getCorpId() {
		return corpId;
	}

	public void setCorpId(String corpId) {
		this.corpId = corpId;
	}

	public String getKey() {
		return key;
	}

	public void setKey(String key) {
		this.key = key;
	}

	public String getToken() {
		return token;
	}

	public void setToken(String token) {
		this.token = token;
	}

	public String getCode() {
		return code;
	}

	public void setCode(String code) {
		this.code = code;
	}

	public String getAccessToken() {
		return accessToken;
	}

	public void setAccessToken(String accessToken) {
		this.accessToken = accessToken;
	}

}
