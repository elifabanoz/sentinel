package io.sentinel.gateway.ratelimit;

import io.sentinel.gateway.user.User;
import jakarta.servlet.FilterChain;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.junit.jupiter.MockitoExtension;
import org.springframework.data.redis.core.StringRedisTemplate;
import org.springframework.data.redis.core.script.RedisScript;
import org.springframework.mock.web.MockHttpServletRequest;
import org.springframework.mock.web.MockHttpServletResponse;
import org.springframework.security.authentication.UsernamePasswordAuthenticationToken;
import org.springframework.security.core.context.SecurityContextHolder;
import org.springframework.test.util.ReflectionTestUtils;

import java.util.List;
import java.util.UUID;

import static org.assertj.core.api.Assertions.assertThat;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.Mockito.*;

@ExtendWith(MockitoExtension.class)
class RateLimitFilterTest {

    @Mock
    StringRedisTemplate redisTemplate;

    @Mock
    FilterChain filterChain;

    RateLimitFilter filter;

    @BeforeEach
    void setUp() {
        filter = new RateLimitFilter(redisTemplate);
    }

    @AfterEach
    void tearDown() {
        SecurityContextHolder.clearContext();
    }

    @Test
    void allowsRequestUnderAuthLimit() throws Exception {
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any())).thenReturn(1L);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        assertThat(response.getStatus()).isEqualTo(200);
    }

    @Test
    void blocksRequestOverAuthLimit() throws Exception {
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any())).thenReturn(6L);

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/auth/login");
        request.setRemoteAddr("10.0.0.1");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(429);
        assertThat(response.getHeader("Retry-After")).isEqualTo("1");
    }

    @Test
    void doesNotRateLimitUnauthenticatedScanCreation() throws Exception {
        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/scans");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain).doFilter(request, response);
        verifyNoInteractions(redisTemplate);
    }

    @Test
    void blocksScanCreationOverLimitForAuthenticatedUser() throws Exception {
        when(redisTemplate.execute(any(RedisScript.class), anyList(), any())).thenReturn(11L);

        User user = new User();
        ReflectionTestUtils.setField(user, "id", UUID.randomUUID());
        SecurityContextHolder.getContext().setAuthentication(
                new UsernamePasswordAuthenticationToken(user, null, List.of()));

        MockHttpServletRequest request = new MockHttpServletRequest("POST", "/scans");
        MockHttpServletResponse response = new MockHttpServletResponse();

        filter.doFilter(request, response, filterChain);

        verify(filterChain, never()).doFilter(any(), any());
        assertThat(response.getStatus()).isEqualTo(429);
    }
}
