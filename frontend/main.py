import flet as ft
import requests

API_URL = "https://jp-chat-friends-sy2005.onrender.com"  # Use your actual backend URL

def main(page: ft.Page):
    page.title = "Flet Chat System"
    page.horizontal_alignment = ft.CrossAxisAlignment.CENTER
    page.vertical_alignment = ft.MainAxisAlignment.CENTER
    page.bgcolor = ft.colors.BLUE_50

    def go_to_login(e):
        page.clean()
        login_view()

    def login_click(e):
        r = requests.post(f"{API_URL}/login", json={
            "username": username.value,
            "password": password.value
        })
        if r.status_code == 200:
            page.clean()
            page.add(
                ft.Column([
                    ft.Text(f"✅ Welcome, {username.value}!", size=24, weight="bold"),
                    ft.ElevatedButton("Logout", on_click=lambda e: home_view())
                ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
            )
        else:
            page.snack_bar = ft.SnackBar(ft.Text("❌ Login failed"), open=True)
            page.update()

    def home_view():
        page.clean()
        page.add(
            ft.Column([
                ft.Text("💬 Welcome to Chat Friends!", size=30, weight="bold", color=ft.colors.BLUE_900),
                ft.Text("A simple and secure messaging system.", size=16),
                ft.ElevatedButton("Login", on_click=go_to_login),
                ft.Text("Built with Flet + Flask + PostgreSQL", size=12, italic=True, color=ft.colors.GREY_600)
            ], alignment=ft.MainAxisAlignment.CENTER, horizontal_alignment=ft.CrossAxisAlignment.CENTER)
        )

    def login_view():
        page.clean()
        page.add(
            ft.Column([
                ft.Text("🔐 Login", size=24, weight="bold"),
                username,
                password,
                ft.ElevatedButton("Login", on_click=login_click),
                ft.TextButton("← Back", on_click=lambda e: home_view())
            ], width=300, spacing=10)
        )

    # Shared fields
    username = ft.TextField(label="Username", autofocus=True)
    password = ft.TextField(label="Password", password=True, can_reveal_password=True)

    # Show home page first
    home_view()

ft.app(target=main)
