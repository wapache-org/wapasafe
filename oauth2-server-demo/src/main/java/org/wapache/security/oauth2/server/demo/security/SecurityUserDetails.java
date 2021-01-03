package org.wapache.security.oauth2.server.demo.security;

import org.wapache.security.oauth2.server.demo.entity.User;
import org.springframework.security.core.GrantedAuthority;
import org.springframework.security.core.userdetails.UserDetails;

import java.util.Collection;
import java.util.Collections;

public class SecurityUserDetails implements UserDetails {

    public static final String SPLIT_CHAR = ":";

    User user;

    public SecurityUserDetails(User user) {
        this.user = user;
    }

    public User getUser() {
        return user;
    }

    //security存储权限认证用的
    private Collection<? extends GrantedAuthority> authorities = Collections.emptyList();

    @Override
    public Collection<? extends GrantedAuthority> getAuthorities() {
        return authorities;
    }

    @Override
    public String getPassword() {
        return user.getPassword();
    }

    @Override
    public String getUsername() {
        return user.getUsername();
    }

    /**
     * 用户账号是否过期
     * true: 未过期
     * false: 已过期
     * @return
     */
    @Override
    public boolean isAccountNonExpired() {
        return true;
    }

    /**
     * 用户账号是否被锁定
     * true: 未锁定
     * false: 锁定
     * @return
     */
    @Override
    public boolean isAccountNonLocked() {
        return true;
    }

    /**
     * 用户账号凭证(密码)是否过期
     * 简单的说就是可能会因为修改了密码导致凭证过期这样的场景
     * true: 过期
     * false: 无效
     * @return
     */
    @Override
    public boolean isCredentialsNonExpired() {
        return true;
    }

    /**
     * 用户账号是否被启用
     * true: 启用
     * false: 未启用
     * @return
     */
    @Override
    public boolean isEnabled() {
        return true;
    }

}
