package org.wapache.security.oauth2.server.demo.dao;

import org.wapache.security.oauth2.server.demo.entity.User;

import java.util.List;

public interface UserDao {

    User createUser(User user);

    User updateUser(User user);

    void deleteUser(Long userId);

    User findOne(Long userId);

    List<User> findAll();

    User findByUsername(String username);

}
