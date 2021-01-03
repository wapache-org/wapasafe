package org.wapache.security.oauth2.server.demo.security;

import org.wapache.security.oauth2.server.demo.entity.User;
import org.wapache.security.oauth2.server.demo.service.UserService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.security.core.userdetails.UserDetailsService;
import org.springframework.security.core.userdetails.UsernameNotFoundException;
import org.springframework.stereotype.Service;

@Service
public class SecurityUserDetailsService implements UserDetailsService {

    @Autowired
    private UserService userService;

    @Override
    public SecurityUserDetails loadUserByUsername(String username) throws UsernameNotFoundException {
        User user = userService.findByUsername(username);
        if (user == null) {
            throw new UsernameNotFoundException("不存在该用户!");
        }
        return new SecurityUserDetails(user);
    }

}