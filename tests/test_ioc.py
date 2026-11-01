from ioc_enricher.ioc import classify, defang, extract, refang


def test_refang_and_defang():
    assert refang("hxxps://evil[.]com/a") == "https://evil.com/a"
    assert refang("1[.]2[.]3[.]4") == "1.2.3.4"
    assert defang("http://evil.com") == "hxxp://evil[.]com"


def test_classify_types():
    assert classify("8.8.8.8").type == "ipv4"
    assert classify("2001:db8::1").type == "ipv6"
    assert classify("Evil[.]Example[.]com").value == "evil.example.com"
    assert classify("a" * 32).type == "md5"
    assert classify("a" * 40).type == "sha1"
    assert classify("a" * 64).type == "sha256"
    assert classify("hxxp://x[.]io/p?q=1").type == "url"
    assert classify("Bob@Evil.com").type == "email"


def test_classify_rejects_garbage():
    assert classify("not an ioc") is None
    assert classify("999.1.1.1") is None
    assert classify("") is None


def test_extract_dedupes_and_ignores_comments():
    text = "# comment evil.com\nC2 at 1[.]2[.]3[.]4 and 1.2.3.4\nsee hxxp://bad[.]org/x"
    vals = [i.value for i in extract(text)]
    assert vals.count("1.2.3.4") == 1
    assert "http://bad.org/x" in vals
    assert "evil.com" not in vals
