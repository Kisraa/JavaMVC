package vn.hoidanit.laptopshop.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.RequestMapping;

import vn.hoidanit.laptopshop.service.UserService;

@Controller
public class UserController {

    private UserService UserService;

    public UserController(UserService userService) {
        UserService = userService;
    }

    @RequestMapping("/")
    public String getHomePage() {
        return "eric.html";
    }
}
// @RestController
// public class UserController {

// private UserService UserService;

// public UserController(UserService userService) {
// UserService = userService;
// }

// @GetMapping("/")
// public String getHomePage() {
// return this.UserService.handleHello();
// }
// }