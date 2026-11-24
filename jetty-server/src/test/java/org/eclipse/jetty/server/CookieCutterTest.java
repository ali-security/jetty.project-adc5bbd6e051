//
//  ========================================================================
//  Copyright (c) 1995-2018 Mort Bay Consulting Pty. Ltd.
//  ------------------------------------------------------------------------
//  All rights reserved. This program and the accompanying materials
//  are made available under the terms of the Eclipse Public License v1.0
//  and Apache License v2.0 which accompanies this distribution.
//
//      The Eclipse Public License is available at
//      http://www.eclipse.org/legal/epl-v10.html
//
//      The Apache License v2.0 is available at
//      http://www.opensource.org/licenses/apache2.0.php
//
//  You may elect to redistribute this code under either of these licenses.
//  ========================================================================
//

package org.eclipse.jetty.server;

import static org.hamcrest.Matchers.containsString;
import static org.hamcrest.Matchers.is;
import static org.hamcrest.Matchers.not;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThat;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.servlet.http.Cookie;

import org.junit.Test;

public class CookieCutterTest
{
    private static Cookie[] parseCookieHeaders(String... headers)
    {
        CookieCutter cutter = new CookieCutter();
        for (String header : headers)
        {
            cutter.addCookieField(header);
        }
        return cutter.getCookies();
    }

    private static List<String> toNameValues(Cookie[] cookies)
    {
        List<String> nameValues = new ArrayList<>();
        for (Cookie cookie : cookies)
        {
            nameValues.add(cookie.getName() + "=" + cookie.getValue());
        }
        return nameValues;
    }

    private static void assertCookies(String input, String... expected)
    {
        assertThat("Cookies of <" + input + ">", toNameValues(parseCookieHeaders(input)), is(Arrays.asList(expected)));
    }

    /**
     * CVE-2023-26049: a ';' inside a quoted value must not let that cookie absorb the following cookies.
     */
    @Test
    public void testQuotedSemicolonRejectsCookie()
    {
        assertCookies("A=\"1; B=2\"; C=3", "C=3");
        assertCookies("name=value; other=\"quoted=;value\"", "name=value");
        assertCookies("SESSION=1234; other=\"quoted=;HttpOnly_cookie=secret\"", "SESSION=1234");
        assertCookies("A=\"1; B=2\"");
    }

    /**
     * CVE-2023-26049: an escaped ';' inside a quoted value is still a ';'.
     */
    @Test
    public void testEscapedQuotedSemicolonRejectsCookie()
    {
        assertCookies("A=\"1\\; B=2\"; C=3", "C=3");
        assertCookies("A=\"1\\;\"; C=3", "C=3");
    }

    /**
     * CVE-2023-26049: an unterminated quote must not yield a cookie that absorbed the rest of the header.
     */
    @Test
    public void testUnterminatedQuoteDoesNotAbsorbFollowingCookies()
    {
        assertCookies("A=\"1; B=2; C=3");
        assertCookies("X=0; A=\"1; B=2; C=3", "X=0");
        assertCookies("A=\"1\\; B=2; C=3");
    }

    /**
     * CVE-2023-26049: the rejection only applies to the cookie field holding the quoted ';'.
     */
    @Test
    public void testRejectedCookieAcrossFields()
    {
        assertThat(toNameValues(parseCookieHeaders("A=\"1; B=2\"", "C=3")), is(Arrays.asList("C=3")));
        assertThat(toNameValues(parseCookieHeaders("A=\"1; B=2", "C=3")), is(Arrays.asList("C=3")));
    }

    /**
     * CVE-2023-26049: the attributes following a rejected cookie must not be applied to the previous cookie.
     */
    @Test
    public void testRejectedCookieDoesNotTakeFollowingAttributes()
    {
        Cookie[] cookies = parseCookieHeaders("A=1; B=\"2; C=3\"; $Path=/p; $Domain=example.com");
        assertEquals(1, cookies.length);
        assertEquals("A", cookies[0].getName());
        assertEquals("1", cookies[0].getValue());
        assertNull(cookies[0].getPath());
        assertNull(cookies[0].getDomain());

        cookies = parseCookieHeaders("A=1; $Path=/p; B=\"2; C=3\"; $Domain=example.com");
        assertEquals(1, cookies.length);
        assertEquals("A", cookies[0].getName());
        assertEquals("1", cookies[0].getValue());
        assertEquals("/p", cookies[0].getPath());
        assertNull(cookies[0].getDomain());
    }

    /**
     * CVE-2023-26049 / GHSA-p26g-97m4-6q7c: an attacker controlled cookie with a quoted value
     * must not smuggle the value of a following (possibly HttpOnly) cookie.
     */
    @Test
    public void testCookieSmuggling()
    {
        String[] inputs = {
            // The advisory example
            "DISPLAY_LANGUAGE=\"b; JSESSIONID=1337; c=d\"",
            // Smuggled cookie last, so the quote is never terminated
            "DISPLAY_LANGUAGE=\"b; JSESSIONID=1337",
            // The ';' separator escaped by a trailing backslash in the attacker controlled value
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337",
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337\"",
            "DISPLAY_LANGUAGE=\"b\\; JSESSIONID=1337; c=d\""
        };

        for (String input : inputs)
        {
            Cookie[] cookies = parseCookieHeaders(input);
            for (Cookie cookie : cookies)
            {
                assertThat("Cookie.name of <" + input + ">", cookie.getName(), not(is("DISPLAY_LANGUAGE")));
                assertThat("Cookie.value of <" + input + ">", cookie.getValue(), not(containsString("JSESSIONID")));
                assertThat("Cookie.value of <" + input + ">", cookie.getValue(), not(containsString("1337")));
            }
            assertCookies(input);
        }
    }

    /**
     * The parsing of cookies without a ';' inside a quoted section is unchanged by the CVE-2023-26049 fix.
     */
    @Test
    public void testUnchangedBehaviour()
    {
        assertCookies("A=1; B=2; C=3", "A=1", "B=2", "C=3");
        assertCookies("A=\"1\"; B=2; C=3", "A=1", "B=2", "C=3");
        assertCookies("A=\"1 B=2\"; C=3", "A=1 B=2", "C=3");
        assertCookies("A=\"1,\"; B=2; C=3", "A=1,", "B=2", "C=3");
        assertCookies("A=\"\\1\"; B=2; C=3", "A=1", "B=2", "C=3");
        assertCookies("A=\"1\\\"2\"; B=3", "A=1\"2", "B=3");
        assertCookies("name=quoted=\"\\\"value\\\"\"", "name=quoted=\"value\"");
    }
}
