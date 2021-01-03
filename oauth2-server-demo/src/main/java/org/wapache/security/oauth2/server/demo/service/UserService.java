package org.wapache.security.oauth2.server.demo.service;

import org.wapache.security.oauth2.server.demo.entity.User;

import java.util.List;

public interface UserService {
    /**
     * 创建用户
     *
     * @param user
     */
    User createUser(User user);

    User updateUser(User user);

    void deleteUser(Long userId);

    /**
     * 修改密码
     *
     * @param userId
     * @param newPassword
     */
    void changePassword(Long userId, String newPassword);

    User findOne(Long userId);

    List<User> findAll();

    /**
     * 根据用户名查找用户
     *
     * @param username
     * @return
     */
    User findByUsername(String username);

}
