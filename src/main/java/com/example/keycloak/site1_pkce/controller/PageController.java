package com.example.keycloak.site1_pkce.controller;

import jakarta.servlet.http.HttpServletResponse;
import org.springframework.core.io.ClassPathResource;
import org.springframework.stereotype.Controller;
import org.springframework.util.StreamUtils;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RequestMapping;
import org.springframework.web.bind.annotation.ResponseBody;

import java.io.IOException;

@Controller
public class PageController {
    @RequestMapping("/favicon.ico")
    @ResponseBody
    void favicon(HttpServletResponse response) throws IOException {
        ClassPathResource res = new ClassPathResource("static/favicon.ico");
        StreamUtils.copy(res.getInputStream(), response.getOutputStream());
    }

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
    public String goMyAccount() {
        System.out.println("goMyAccount()...");
        return "/login/myaccount";
    }

    @GetMapping(value = "/mypage")
    public String goMyPage() {
        System.out.println("goMyPage()...");
        return "/login/mypage";
    }

    @GetMapping(value = "/guest")
    public String gotoGeust() {
        System.out.println("gotMyPage()...");
        return "/login/page_guest_3";
    }
}
