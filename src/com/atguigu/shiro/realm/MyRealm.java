package com.atguigu.shiro.realm;

import java.util.HashSet;
import java.util.Set;

import org.apache.shiro.authc.AuthenticationException;
import org.apache.shiro.authc.AuthenticationInfo;
import org.apache.shiro.authc.AuthenticationToken;
import org.apache.shiro.authc.SimpleAuthenticationInfo;
import org.apache.shiro.authc.UsernamePasswordToken;
import org.apache.shiro.authz.AuthorizationInfo;
import org.apache.shiro.authz.SimpleAuthorizationInfo;
import org.apache.shiro.realm.AuthorizingRealm;
import org.apache.shiro.subject.PrincipalCollection;
import org.apache.shiro.util.ByteSource;

public class MyRealm extends AuthorizingRealm {

	@Override
	protected AuthorizationInfo doGetAuthorizationInfo(
			PrincipalCollection principals) {
		Object principal = principals.getPrimaryPrincipal();
		Set<String> roles = new HashSet<>();
		roles.add("user");
		if("admin".equals(principal)) {
			roles.add("admin");
		} else if ("test".equals(principal)) {
			roles.add("test");
		}
		// 3. 创建 SimpleAuthorizationInfo 对象, 并加入权限
		SimpleAuthorizationInfo info = new SimpleAuthorizationInfo();
		info.addRoles(roles);

		// 4. 返回
		return info;
	}

	@Override
	protected AuthenticationInfo doGetAuthenticationInfo(
			AuthenticationToken token) throws AuthenticationException {
		// 1. 把 AuthenticationToken 参数强转为 UsernamePasswordToken
		UsernamePasswordToken upToken = (UsernamePasswordToken) token;

		// 2. 从 UsernamePasswordToken 中获取 username
		String username = upToken.getUsername();

		// 3. 利用 username 查询数据表, 获取用户的信息
		System.out.println("利用页面传入的 " + username + " 从数据库中获取用户信息");

		// principal: 认证成功后的实体信息。 可以是 username, 也可以是一个对象.
		Object principal = username;
		// credentials: 凭证. 即密码. 是用 username 从数据库中获取的!
		// Object credentials = "123456";
		Object hashedCredentials = null;

		if ("admin".equals(username)) {
			hashedCredentials = "038bdaf98f2037b31f1e75b5b4c9b26e";
		} else if ("user".equals(username)) {
			hashedCredentials = "098d2c478e9c11555ce2823231e02ec1";
		}

		// 盐值: 从数据表中查询的得到的.
		String salt = username;
		ByteSource credentialsSalt = ByteSource.Util.bytes(salt);
		// realmName: 当前 Realm 的名字. 直接调用父类的 getName() 方法即可.
		String realmName = getName();

		// 4. 利用从数据库中获取的用户信息来创建 SimpleAuthenticationInfo 对象并返回
		SimpleAuthenticationInfo info = null;
		// info = new SimpleAuthenticationInfo(principal, credentials,
		// realmName);
		// 对密码的盐值加密.
		info = new SimpleAuthenticationInfo(principal, hashedCredentials,
				credentialsSalt, realmName);

		return info;
	}

}
