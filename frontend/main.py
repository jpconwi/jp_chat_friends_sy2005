import flet as ft
import requests

API_URL = "https://chat-backend.onrender.com"

def main(page: ft.Page):
    page.title = "Flet Chat App"
    
    def login_click(e):
        r = requests.post(f"{API_URL}/login", json={
            "username": username.value,
            "password": password.value
        })
        if r.status_code == 200:
            page.clean()
            page.controls.append(ft.Text("Welcome!"))
        else:
            page.snack_bar = ft.SnackBar(ft.Text("Login failed"), open=True)
            page.update()

    username = ft.TextField(label="Username")
    password = ft.TextField(label="Password", password=True)

    page.add(username, password, ft.ElevatedButton("Login", on_click=login_click))

ft.app(target=main)
