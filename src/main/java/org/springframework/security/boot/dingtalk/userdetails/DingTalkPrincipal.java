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
package org.springframework.security.boot.dingtalk.userdetails;

import org.springframework.security.boot.biz.userdetails.SecurityPrincipal;
import org.springframework.security.core.GrantedAuthority;

import java.util.Collection;

/**
 * TODO
 * 
 * @author ： <a href="https://github.com/hiwepy">wandl</a>
 */
@SuppressWarnings("serial")
public class DingTalkPrincipal extends SecurityPrincipal {

	/**
	 * 员工在当前企业内的唯一标识，也称staffId。可由企业在创建时指定，并代表一定含义比如工号，创建后不可修改
	 */
	protected String userid;
	/**
	 * 员工在当前开发者企业账号范围内的唯一标识，系统生成，固定值，不会改变
	 */
	protected String unionid;
	/**
	 * 员工名字
	 */
	protected String name;
	/**
	 * 分机号（仅限企业内部开发调用）
	 */
	protected String tel;
	/**
	 * 办公地点
	 */
	protected String workPlace;
	/**
	 * 备注
	 */
	protected String remark;
	/**
	 * 手机号码
	 */
	protected String mobile;
	/**
	 * 员工的电子邮箱
	 */
	protected String email;
	/**
	 * 员工的企业邮箱，如果员工已经开通了企业邮箱，接口会返回，否则不会返回
	 */
	protected String orgEmail;
	/**
	 * 是否已经激活，true表示已激活，false表示未激活
	 */
	protected String active;
	/**
	 * 在对应的部门中的排序，Map结构的json字符串，key是部门的Id，value是人员在这个部门的排序值
	 */
	protected String orderInDepts;
	/**
	 * 是否为企业的管理员，true表示是，false表示不是
	 */
	protected boolean admin;
	/**
	 * 是否为企业的老板，true表示是，false表示不是
	 */
	protected boolean boss;
	/**
	 * 在对应的部门中是否为主管：Map结构的json字符串，key是部门的Id，value是人员在这个部门中是否为主管，true表示是，false表示不是
	 */
	protected boolean leaderInDepts;
	/**
	 * 是否号码隐藏，true表示隐藏，false表示不隐藏
	 */
	protected boolean hide;
	/**
	 * 成员所属部门id列表
	 */
	protected String department;
	/**
	 * 职位信息
	 */
	protected String position;
	/**
	 * 头像url
	 */
	protected String avatar;
	/**
	 * 入职时间。Unix时间戳 （在OA后台通讯录中的员工基础信息中维护过入职时间才会返回)
	 */
	protected String hiredDate;
	/**
	 * 员工工号
	 */
	protected String jobnumber;
	/**
	 * 扩展属性，可以设置多种属性（但手机上最多只能显示10个扩展属性，具体显示哪些属性，请到OA管理后台-&gt;设置-&gt;通讯录信息设置和OA管理后台-&gt;设置-&gt;手机端显示信息设置）
	 */
	protected String extattr;
	/**
	 * 是否是高管
	 */
	protected boolean senior;
	/**
	 * 国家地区码
	 */
	protected String stateCode;

	public DingTalkPrincipal(String username, String password, String... roles) {
		super(username, password, roles);
	}

	public DingTalkPrincipal(String username, String password, Collection<? extends GrantedAuthority> authorities) {
		super(username, password, authorities);
	}

	public DingTalkPrincipal(String username, String password, boolean enabled, boolean accountNonExpired,
			boolean credentialsNonExpired, boolean accountNonLocked,
			Collection<? extends GrantedAuthority> authorities) {
		super(username, password, enabled, accountNonExpired, credentialsNonExpired, accountNonLocked, authorities);
	}

	public String getUserid() {
		return userid;
	}

	public String getUnionid() {
		return unionid;
	}

	public String getName() {
		return name;
	}

	public String getTel() {
		return tel;
	}

	public String getWorkPlace() {
		return workPlace;
	}

	public String getRemark() {
		return remark;
	}

	public String getMobile() {
		return mobile;
	}

	public String getEmail() {
		return email;
	}

	public String getOrgEmail() {
		return orgEmail;
	}

	public String getActive() {
		return active;
	}

	public String getOrderInDepts() {
		return orderInDepts;
	}

	public boolean isAdmin() {
		return admin;
	}

	public boolean isBoss() {
		return boss;
	}

	public boolean isLeaderInDepts() {
		return leaderInDepts;
	}

	public boolean isHide() {
		return hide;
	}

	public String getDepartment() {
		return department;
	}

	public String getPosition() {
		return position;
	}

	public String getAvatar() {
		return avatar;
	}

	public String getHiredDate() {
		return hiredDate;
	}

	public String getJobnumber() {
		return jobnumber;
	}

	public String getExtattr() {
		return extattr;
	}

	public boolean isSenior() {
		return senior;
	}

	public String getStateCode() {
		return stateCode;
	}

	public void setUserid(String userid) {
		this.userid = userid;
	}

	public void setUnionid(String unionid) {
		this.unionid = unionid;
	}

	public void setName(String name) {
		this.name = name;
	}

	public void setTel(String tel) {
		this.tel = tel;
	}

	public void setWorkPlace(String workPlace) {
		this.workPlace = workPlace;
	}

	public void setRemark(String remark) {
		this.remark = remark;
	}

	public void setMobile(String mobile) {
		this.mobile = mobile;
	}

	public void setEmail(String email) {
		this.email = email;
	}

	public void setOrgEmail(String orgEmail) {
		this.orgEmail = orgEmail;
	}

	public void setActive(String active) {
		this.active = active;
	}

	public void setOrderInDepts(String orderInDepts) {
		this.orderInDepts = orderInDepts;
	}

	public void setAdmin(boolean admin) {
		this.admin = admin;
	}

	public void setBoss(boolean boss) {
		this.boss = boss;
	}

	public void setLeaderInDepts(boolean leaderInDepts) {
		this.leaderInDepts = leaderInDepts;
	}

	public void setHide(boolean hide) {
		this.hide = hide;
	}

	public void setDepartment(String department) {
		this.department = department;
	}

	public void setPosition(String position) {
		this.position = position;
	}

	public void setAvatar(String avatar) {
		this.avatar = avatar;
	}

	public void setHiredDate(String hiredDate) {
		this.hiredDate = hiredDate;
	}

	public void setJobnumber(String jobnumber) {
		this.jobnumber = jobnumber;
	}

	public void setExtattr(String extattr) {
		this.extattr = extattr;
	}

	public void setSenior(boolean senior) {
		this.senior = senior;
	}

	public void setStateCode(String stateCode) {
		this.stateCode = stateCode;
	}

}
