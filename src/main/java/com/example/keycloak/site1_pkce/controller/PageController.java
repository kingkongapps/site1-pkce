package com.example.keycloak.site1_pkce.controller;

import org.springframework.stereotype.Controller;
import org.springframework.web.bind.annotation.GetMapping;

@Controller
public class PageController {
    @GetMapping(value = "/")
    public String goHome() {
        System.out.println("goHome()...");
        return "/home";
    }

    @GetMapping(value = "/login")
    public String goLogin() {
        System.out.println("goLogin()...");
        return "/login/login";
    }

    @GetMapping(value = "/logout")
    public String goLogout() {
        System.out.println("goLogout()...");
        return "/login/logout";
    }

    @GetMapping(value = "/myaccount")
    public String gotMyAccount() {
        System.out.println("gotMyAccount()...");
        return "/login/myaccount";
    }

    @GetMapping(value = "/mypage")
    public String gotMyPage() {
        System.out.println("gotMyPage()...");
        return "/login/mypage";
    }

}
