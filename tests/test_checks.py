import unittest

from header_audit.checks import AVISO, FALHA, INFO, OK, avaliar, nota, verificar_cookies, verificar_csp, \
    verificar_exposicao, verificar_frames, verificar_hsts, verificar_https, verificar_referrer

SITE = "https://exemplo.com.br/"


def h(**pares):
    """Monta cabeçalhos no formato normalizado: h(content_security_policy="...")."""
    return {nome.replace("_", "-"): [valor] if isinstance(valor, str) else valor for nome, valor in pares.items()}


class TestHttps(unittest.TestCase):
    def test_http_sem_criptografia_e_falha(self):
        self.assertEqual(verificar_https("http://exemplo.com.br/", None)[0].status, FALHA)

    def test_https_sem_redirecionamento_do_http_e_aviso(self):
        self.assertEqual(verificar_https(SITE, False)[0].status, AVISO)

    def test_https_com_redirecionamento_e_ok(self):
        self.assertEqual(verificar_https(SITE, True)[0].status, OK)


class TestHsts(unittest.TestCase):
    def test_ausente(self):
        self.assertEqual(verificar_hsts({}, True)[0].status, FALHA)

    def test_max_age_curto(self):
        self.assertEqual(verificar_hsts(h(strict_transport_security="max-age=300"), True)[0].status, AVISO)

    def test_sem_subdominios(self):
        self.assertEqual(verificar_hsts(h(strict_transport_security="max-age=31536000"), True)[0].status, INFO)

    def test_completo(self):
        valor = "max-age=31536000; includeSubDomains; preload"
        self.assertEqual(verificar_hsts(h(strict_transport_security=valor), True)[0].status, OK)

    def test_ignorado_em_http(self):
        self.assertEqual(verificar_hsts({}, False), [])


class TestCsp(unittest.TestCase):
    def test_ausente(self):
        self.assertEqual(verificar_csp({})[0].status, FALHA)

    def test_so_relatorio(self):
        self.assertEqual(verificar_csp(h(content_security_policy_report_only="default-src 'self'"))[0].status, AVISO)

    def test_unsafe_inline(self):
        achado = verificar_csp(h(content_security_policy="default-src 'self'; script-src 'self' 'unsafe-inline'"))[0]
        self.assertEqual(achado.status, AVISO)
        self.assertIn("'unsafe-inline'", achado.detalhe)

    def test_sem_fonte_de_scripts(self):
        self.assertEqual(verificar_csp(h(content_security_policy="img-src 'self'"))[0].status, AVISO)

    def test_politica_restrita(self):
        self.assertEqual(verificar_csp(h(content_security_policy="default-src 'self'; object-src 'none'"))[0].status, OK)


class TestOutros(unittest.TestCase):
    def test_frame_ancestors_vale_como_protecao(self):
        self.assertEqual(verificar_frames(h(content_security_policy="frame-ancestors 'none'"))[0].status, OK)

    def test_sem_protecao_de_frames(self):
        self.assertEqual(verificar_frames({})[0].status, FALHA)

    def test_referrer_inseguro(self):
        self.assertEqual(verificar_referrer(h(referrer_policy="unsafe-url"))[0].status, AVISO)

    def test_versao_exposta(self):
        achados = verificar_exposicao(h(server="nginx/1.18.0", x_powered_by="PHP/8.1.2"))
        self.assertEqual([a.status for a in achados], [AVISO, AVISO])

    def test_servidor_sem_versao(self):
        self.assertEqual(verificar_exposicao(h(server="cloudflare"))[0].status, OK)

    def test_cookie_sem_atributos(self):
        achado = verificar_cookies(h(set_cookie="sessao=abc123; Path=/"), True)[0]
        self.assertEqual(achado.status, AVISO)
        self.assertIn("Secure", achado.detalhe)

    def test_cookie_completo(self):
        cookie = "sessao=abc123; Path=/; Secure; HttpOnly; SameSite=Lax"
        self.assertEqual(verificar_cookies(h(set_cookie=cookie), True)[0].status, OK)


class TestNota(unittest.TestCase):
    def test_site_bem_configurado_tira_a(self):
        headers = h(
            strict_transport_security="max-age=31536000; includeSubDomains",
            content_security_policy="default-src 'self'; frame-ancestors 'self'",
            x_content_type_options="nosniff",
            referrer_policy="strict-origin-when-cross-origin",
            permissions_policy="camera=(), microphone=()",
            server="nginx",
        )
        achados = avaliar(headers, SITE, http_redireciona=True, dias_certificado=80)
        self.assertEqual(nota(achados), (100, "A"))

    def test_site_sem_cabecalhos_tira_f(self):
        self.assertEqual(nota(avaliar({}, SITE, http_redireciona=False, dias_certificado=10))[1], "F")

    def test_achados_vem_do_mais_grave(self):
        achados = avaliar({}, SITE, http_redireciona=True, dias_certificado=80)
        self.assertEqual(achados[0].status, FALHA)
        self.assertEqual(achados[-1].status, OK)


if __name__ == "__main__":
    unittest.main()
