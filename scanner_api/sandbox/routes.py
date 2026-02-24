from fastapi import APIRouter, HTTPException
from pydantic import BaseModel
import docker
from typing import Optional
import os

router = APIRouter()
client = docker.from_env()

class SandboxEnvironment(BaseModel):
    name: str
    type: str  # wordpress, drupal, prestashop
    version: str

class SandboxAction(BaseModel):
    name: str

CMS_IMAGES = {
    'wordpress': {
        '6.4.2': 'wordpress:6.4.2',
        '6.3.2': 'wordpress:6.3.2',
        '5.9.3': 'wordpress:5.9.3'
    },
    'drupal': {
        '10.1.6': 'drupal:10.1.6',
        '9.5.11': 'drupal:9.5.11',
        '7.98': 'drupal:7.98'
    },
    'prestashop': {
        '8.1.2': 'prestashop/prestashop:8.1.2',
        '1.7.8.9': 'prestashop/prestashop:1.7.8.9',
        '1.6.1.24': 'prestashop/prestashop:1.6.1.24'
    }
}

def get_container_name(name: str) -> str:
    return f'sandbox-{name}'

@router.post("/create")
async def create_sandbox(env: SandboxEnvironment):
    try:
        container_name = get_container_name(env.name)
        
        # Vérifier si un conteneur avec ce nom existe déjà
        existing = client.containers.list(all=True, filters={'name': container_name})
        if existing:
            raise HTTPException(status_code=400, detail="Un environnement avec ce nom existe déjà")
            
        # Récupérer l'image correspondante
        if env.type not in CMS_IMAGES or env.version not in CMS_IMAGES[env.type]:
            raise HTTPException(status_code=400, detail="Version de CMS non supportée")
            
        image_name = CMS_IMAGES[env.type][env.version]
        
        # Pull de l'image si nécessaire
        try:
            client.images.get(image_name)
        except docker.errors.ImageNotFound:
            client.images.pull(image_name)
            
        # Configuration spécifique selon le CMS
        environment = {}
        ports = {}
        
        if env.type == 'wordpress':
            environment = {
                'WORDPRESS_DB_HOST': f'db-{container_name}',
                'WORDPRESS_DB_USER': 'wordpress',
                'WORDPRESS_DB_PASSWORD': 'wordpress',
                'WORDPRESS_DB_NAME': 'wordpress'
            }
            
        elif env.type == 'drupal':
            environment = {
                'MYSQL_HOST': f'db-{container_name}',
                'MYSQL_USER': 'drupal',
                'MYSQL_PASSWORD': 'drupal',
                'MYSQL_DATABASE': 'drupal'
            }
            
        # Créer le réseau pour l'environnement
        network_name = f'network-{container_name}'
        try:
            network = client.networks.create(
                network_name,
                driver="bridge",
                internal=False  # Pour permettre l'accès depuis l'extérieur
            )
        except docker.errors.APIError as e:
            if 'already exists' not in str(e):
                raise
            network = client.networks.get(network_name)

        # Créer et démarrer le conteneur de base de données
        db_container = client.containers.run(
            'mysql:5.7',
            name=f'db-{container_name}',
            environment={
                'MYSQL_ROOT_PASSWORD': 'root',
                'MYSQL_USER': env.type,
                'MYSQL_PASSWORD': env.type,
                'MYSQL_DATABASE': env.type
            },
            network=network_name,
            detach=True
        )

        # Créer et démarrer le conteneur CMS
        container = client.containers.run(
            image_name,
            name=container_name,
            environment=environment,
            ports={'80/tcp': None},  # Attribution automatique du port
            network=network_name,
            detach=True
        )

        # Récupérer le port mappé
        container.reload()
        port = list(container.ports['80/tcp'][0]['HostPort'])[0]
        
        return {
            "status": "created",
            "name": env.name,
            "url": f"http://localhost:{port}"
        }
        
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/start")
async def start_sandbox(action: SandboxAction):
    try:
        container_name = get_container_name(action.name)
        container = client.containers.get(container_name)
        
        if container.status != 'running':
            container.start()
            container.reload()
            
            # Redémarrer aussi la base de données si nécessaire
            db_container = client.containers.get(f'db-{container_name}')
            if db_container.status != 'running':
                db_container.start()
            
            port = list(container.ports['80/tcp'][0]['HostPort'])[0]
            return {
                "status": "started",
                "url": f"http://localhost:{port}"
            }
            
        return {"status": "already_running"}
        
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Environnement non trouvé")
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.post("/stop")
async def stop_sandbox(action: SandboxAction):
    try:
        container_name = get_container_name(action.name)
        container = client.containers.get(container_name)
        
        if container.status == 'running':
            container.stop()
            
            # Arrêter aussi la base de données
            try:
                db_container = client.containers.get(f'db-{container_name}')
                if db_container.status == 'running':
                    db_container.stop()
            except docker.errors.NotFound:
                pass  # Ignorer si la DB n'existe pas
                
        return {"status": "stopped"}
        
    except docker.errors.NotFound:
        raise HTTPException(status_code=404, detail="Environnement non trouvé")
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=str(e))

@router.delete("/{name}")
async def delete_sandbox(name: str):
    try:
        container_name = get_container_name(name)
        
        # Supprimer le conteneur principal
        try:
            container = client.containers.get(container_name)
            container.remove(force=True)
        except docker.errors.NotFound:
            pass
            
        # Supprimer le conteneur de base de données
        try:
            db_container = client.containers.get(f'db-{container_name}')
            db_container.remove(force=True)
        except docker.errors.NotFound:
            pass
            
        # Supprimer le réseau
        try:
            network = client.networks.get(f'network-{container_name}')
            network.remove()
        except docker.errors.NotFound:
            pass
            
        return {"status": "deleted"}
        
    except docker.errors.APIError as e:
        raise HTTPException(status_code=500, detail=str(e))