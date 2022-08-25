package com.softserve.itacademy.controller;

import com.softserve.itacademy.security.SecurityUser;
import com.softserve.itacademy.service.RoleService;
import com.softserve.itacademy.service.UserService;
import org.springframework.security.core.annotation.AuthenticationPrincipal;
import org.springframework.stereotype.Controller;
import org.springframework.ui.Model;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class HomeController {
    private final UserService userService;
    public HomeController(UserService userService) {
        this.userService = userService;
    }

    @GetMapping({"/", "home"})
    public String home(@AuthenticationPrincipal SecurityUser securityUser) {
        if (securityUser.getRole().equals("ADMIN")) {
            return "redirect:/users/all";
        }
        else {
            return "redirect:/todos/all/users/" + securityUser.getId();
        }
    }
}
