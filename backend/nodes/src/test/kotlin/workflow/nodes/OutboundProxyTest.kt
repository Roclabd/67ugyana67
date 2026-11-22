package workflow.nodes

import org.junit.jupiter.api.AfterEach
import org.junit.jupiter.api.Assertions.*
import org.junit.jupiter.api.Test

class OutboundProxyTest {
    @AfterEach fun reset() { OutboundProxy.configure(null) }

    @Test fun `empty setting keeps direct mode`() {
        assertNull(OutboundProxy.configure(""))
        assertNull(OutboundProxy.configure("  "))
        assertNull(OutboundProxy.current)
    }

    @Test fun `proxy url is parsed and printed without credentials`() {
        val proxy = OutboundProxy.configure("http://127.0.0.1:10809")!!
        assertEquals("127.0.0.1:10809", proxy.toString())
        assertEquals("http://127.0.0.1:10809", proxy.url)
        assertEquals(proxy, OutboundProxy.current)
    }

    @Test fun `malformed proxy settings are rejected`() {
        for (bad in listOf("127.0.0.1:10809", "socks5://127.0.0.1:1080", "http://user:pass@127.0.0.1:10809",
            "http://127.0.0.1", "http://127.0.0.1:10809/path")) {
            assertThrows(IllegalArgumentException::class.java) { OutboundProxy.parse(bad) }
        }
    }

    @Test fun `proxy mode rejects local and private destinations without DNS`() {
        for (host in listOf("localhost", "api.localhost", "printer.local", "db.internal", "127.0.0.1", "10.0.0.5",
            "192.168.1.1", "169.254.169.254", "172.16.0.1", "[::1]", "::1", "2130706433", "0x7f.0.0.1", "198.18.0.5")) {
            assertThrows(IllegalArgumentException::class.java, { OutboundProxy.requireExternalHost(host) }, host)
        }
    }

    @Test fun `proxy mode accepts public names and addresses`() {
        for (host in listOf("github.com", "api.telegram.org", "8.8.8.8", "gitlab.example.org")) {
            OutboundProxy.requireExternalHost(host)
        }
    }

    @Test fun `git arguments use proxy without address pin`() {
        val proxy = OutboundProxy.parse("http://127.0.0.1:10809")
        val args = gitNetworkArgs("github.com", proxy, emptyList())
        assertTrue("http.proxy=http://127.0.0.1:10809" in args)
        assertTrue(args.none { it.contains("curloptResolve") })
    }

    @Test fun `git arguments pin resolved addresses without proxy`() {
        val args = gitNetworkArgs("github.com", null, listOf("140.82.1.1", "2606:50c0::1"))
        assertEquals(listOf("-c", "http.curloptResolve=github.com:443:140.82.1.1,[2606:50c0::1]"), args)
        assertTrue(args.none { it.contains("http.proxy") })
    }
}
