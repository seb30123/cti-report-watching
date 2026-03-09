from bs4 import BeautifulSoup

def html_to_text(html: str | None) -> str:
    if not html : 
        return ""
    soup = BeautifulSoup(html, "lxml")

    for tag in soup(["script", "style"]) : 
        tag.decompose()
    text = soup.get_text(" ", strip= True)

    return " ".join(text.split())