package io.sentinel.gateway.ratelimit;

import io.sentinel.gateway.user.User;
import jakarta.servlet.FilterChain;
import jakarta.servlet.ServletException;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.DefaultRedisScript;
import org.springframework.security.core.Authentication;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.stereotype.Component;
import org.springframework.web.filter.OncePerRequestFilter;

import java.io.IOException;
import java.util.List;

/**
 * Redis-backed fixed-window rate limiter.
 *
 * - /auth/** is limited per client IP (protects against credential-stuffing/brute force).
 * - POST /scans is limited per authenticated user (protects scanner workers from being flooded).
 */
@Component
public class RateLimitFilter extends OncePerRequestFilter {

    private static final String INCR_AND_EXPIRE_SCRIPT =
            "local count = redis.call('INCR', KEYS[1]) " +
            "if count == 1 then redis.call('EXPIRE', KEYS[1], ARGV[1]) end " +
            "return count";

    private static final int AUTH_LIMIT = 5;
    private static final int AUTH_WINDOW_SECONDS = 1;

    private static final int SCAN_LIMIT = 10;
    private static final int SCAN_WINDOW_SECONDS = 60;

    private final StringRedisTemplate redisTemplate;
    private final DefaultRedisScript<Long> incrAndExpireScript;

    public RateLimitFilter(StringRedisTemplate redisTemplate) {
        this.redisTemplate = redisTemplate;
        this.incrAndExpireScript = new DefaultRedisScript<>(INCR_AND_EXPIRE_SCRIPT, Long.class);
    }

    @Override
    protected void doFilterInternal(HttpServletRequest request,
                                    HttpServletResponse response,
                                    FilterChain filterChain) throws ServletException, IOException {

        RateLimit limit = resolveLimit(request);

        if (limit != null) {
            long count = redisTemplate.execute(
                    incrAndExpireScript,
                    List.of(limit.key()),
                    String.valueOf(limit.windowSeconds())
            );

            if (count > limit.maxRequests()) {
                response.setStatus(429);
                response.setHeader("Retry-After", String.valueOf(limit.windowSeconds()));
                response.setContentType("application/json");
                response.getWriter().write("{\"error\":\"Rate limit exceeded, try again later\"}");
                return;
            }
        }

        filterChain.doFilter(request, response);
    }

    private RateLimit resolveLimit(HttpServletRequest request) {
        String path = request.getRequestURI();

        if (path.startsWith("/auth/")) {
            return new RateLimit("ratelimit:auth:" + request.getRemoteAddr(), AUTH_LIMIT, AUTH_WINDOW_SECONDS);
        }

        if (path.equals("/scans") && "POST".equalsIgnoreCase(request.getMethod())) {
            String userId = currentUserId();
            if (userId == null) {
                return null;
            }
            return new RateLimit("ratelimit:scan:" + userId, SCAN_LIMIT, SCAN_WINDOW_SECONDS);
        }

        return null;
    }

    private String currentUserId() {
        Authentication auth = SecurityContextHolder.getContext().getAuthentication();
        if (auth == null || !(auth.getPrincipal() instanceof User user)) {
            return null;
        }
        return user.getId().toString();
    }

    private record RateLimit(String key, int maxRequests, int windowSeconds) {}
}
