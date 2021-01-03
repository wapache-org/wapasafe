package org.wapache.security.oauth2.server.demo.web.controller;

import org.wapache.security.oauth2.server.demo.entity.Status;
import org.wapache.security.oauth2.server.demo.entity.User;
import org.wapache.security.oauth2.server.demo.service.UserService;
import io.swagger.v3.oas.annotations.tags.Tag;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.web.bind.annotation.*;

import java.util.List;

@RestController
@RequestMapping("/api/v1")
@Tag(name = "User")
public class UserController {

    @Autowired
    private UserService userService;

    @GetMapping("/users")
    public List<User> list() {
        return userService.findAll();
    }

    @PostMapping(value = "/users/create")
    public User create(User user) {
        return userService.createUser(user);
    }

    @PostMapping(value = "/users/{id}/update")
    public User update(User user) {
        return userService.updateUser(user);
    }

    @DeleteMapping(value = "/users/{id}/delete")
    public Status delete(@PathVariable("id") Long id) {
        userService.deleteUser(id);
        Status status = new Status();
        status.setCode(200);
        status.setMsg("删除成功");
        return status;
    }

    @PostMapping(value = "/users/{id}/changePassword")
    public Status changePassword(@PathVariable("id") Long id, String newPassword) {
        userService.changePassword(id, newPassword);
        Status status = new Status();
        status.setCode(200);
        status.setMsg("修改密码成功");
        return status;
    }

}
