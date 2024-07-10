from django.shortcuts import render, redirect
from django.utils import timezone
from core.models import Evento
from django.contrib.auth.decorators import login_required
from django.contrib.auth import authenticate, login, logout
from django.contrib import messages
from datetime import datetime, timedelta
from django.http import Http404, JsonResponse
from django.contrib.auth.models import User

#def index(request):
#    return redirect ('/agenda/')

def login_user(request):
    if request.method == 'POST':
        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is not None:
            login(request, user)
            return redirect('agenda')
        else:
            messages.error(request, 'Usuário ou senha incorretos.')
    return render(request, 'login.html')

@login_required(login_url='/login/')
def lista_eventos(request):
    usuario= request.user
    data_atual = datetime.now() - timedelta(hours=1)
    evento = Evento.objects.filter(usuario=usuario,
                                   data_evento__gt= data_atual)
    dados = {'eventos': evento}
    return render (request, 'agenda.html', dados)

def logout_user(request):
    logout(request)
    return redirect('/')

def submit_login(request):
    if request.POST:
        username = request.POST.get('username')
        password = request.POST.get('password')
        usuario = authenticate(username=username, password=password)
        if usuario is not None:
            login(request, usuario)
            return redirect ('/')
        else:
            messages.error(request, "Usuário ou Senha invalido")
    return redirect('/')

@login_required(login_url='/login/')
def evento(request):
    id_evento = request.GET.get('id')
    dados = {}
    if id_evento:
        dados['evento'] = Evento.objects.get(id=id_evento)
    return render(request, 'evento.html', dados)

@login_required(login_url='/login/')
def submit_evento(request):
    if request.POST:
        titulo = request.POST.get('titulo')
        data_evento = request.POST.get('data_evento')
        local = request.POST.get('local')
        descrição = request.POST.get('descrição')
        usuario = request.user
        id_evento = request.POST.get('id_evento')
        if id_evento:
            evento = Evento.objects.get(id=id_evento)
            if evento.usuario == usuario:
                evento.titulo = titulo
                evento.descrição = descrição
                evento.data_evento = data_evento
                evento.local = local
                evento.save()  
            #Evento.objects.filter(id=id_evento).update(titulo=titulo,
            #                                            data_evento=data_evento,
            #                                            descrição=descrição,
            #                                            local=local)
        else:
            Evento.objects.create(titulo=titulo,
                                    data_evento=data_evento,
                                    descrição=descrição,
                                    usuario=usuario,
                                    local=local)
    return redirect('/')

@login_required(login_url='/login/')
def delete_evento(request, id_evento):
    usuario = request.user
    try:
        evento = Evento.objects.get(id=id_evento)
    except Exception:
        raise Http404()
    
    if usuario == evento.usuario:
        evento.delete()
    else:
        raise Http404()
    return redirect('/')

@login_required(login_url='/login/')
def json_lista_evento(request):
    usuario= request.user
    evento = Evento.objects.filter(usuario=usuario).values('id', 'titulo')
    return JsonResponse(list(evento), safe=False)

def cadastro(request):
    if request.method == 'POST':
        username = request.POST['username']
        senha = request.POST['senha']
        senha2 = request.POST['senha2']

        if senha == senha2:
            if User.objects.filter(username=username).exists():
                messages.error(request, 'Nome do usuário já existe.')
            else:
                user = User.objects.create_user(username=username, password=senha)
                user.save()
                login(request, user)
                return redirect('/')
        else:
            messages.error(request, 'As senhas não coincidem.')
    return render(request, 'cadastro.html')