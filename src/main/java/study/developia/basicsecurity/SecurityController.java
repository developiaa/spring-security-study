package study.developia.basicsecurity;

import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContext;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.security.web.context.HttpSessionSecurityContextRepository;
import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import javax.servlet.http.HttpSession;

@RestController
public class SecurityController {

    @GetMapping("/")
    public String index() {
        return "home";
    }

    @GetMapping("/loginPage")
    public String loginPage() {
        return "loginPage";
    }

    @GetMapping("/user")
    public String user() {
        return "user";
    }

    @GetMapping("/admin/pay")
    public String adminPay() {
        return "adminPay";
    }

    @GetMapping("/admin/**")
    public String admin() {
        return "admin";
    }

    @GetMapping("/denied")
    public String denied() {
        return "Access is denied";
    }

    @GetMapping("/login")
    public String login() {
        return "login!!";
    }

    @GetMapping("/security-context")
    public String security(HttpSession session) {
        // 두 개는 같은 객체이다.
        Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        SecurityContext securityContext = (SecurityContext) session.getAttribute(HttpSessionSecurityContextRepository.SPRING_SECURITY_CONTEXT_KEY);
        Authentication authentication1 = securityContext.getAuthentication();

        return "home";
    }

    @GetMapping("/thread")
    public String thread() {
        new Thread(() -> {
            // 메인 스레드와 다른 스레드이기 때문에 null이다. (MODE_THREADLOCAL 일 경우)
            Authentication authentication = SecurityContextHolder.getContext().getAuthentication();
        }).start();

        return "thread";
    }

}
