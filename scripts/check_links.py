"""Simple link checker for the Arte Theory Series README.

This script only prints the expected repository links.
It does not perform network requests by default.
"""

REPOS = [
    "https://github.com/leehyen0/bias-as-controlled-asymmetry",
    "https://github.com/leehyen0/complementary-possibility-axes",
    "https://github.com/leehyen0/temporal-superposition-self-transcendence",
    "https://github.com/leehyen0/questionfield-theory",
    "https://github.com/leehyen0/lawgenesis-theory",
]

if __name__ == "__main__":
    print("Expected series repositories:")
    for url in REPOS:
        print("-", url)
