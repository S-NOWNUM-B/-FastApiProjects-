from fastapi import APIRouter, HTTPException, status, Depends, Path
from sqlmodel import select
from sqlmodel.ext.asyncio.session import AsyncSession
from models import Note, NoteCreate, NoteUpdate, NoteOut, User
from database import async_session
from auth import get_current_user

router = APIRouter(
    prefix="/notes",
    tags=["Notes"],
    responses={
        401: {
            "description": "Не аутентифицирован",
            "content": {
                "application/json": {
                    "example": {"detail": "Not authenticated"}
                }
            }
        }
    }
)

@router.post(
    "/",
    response_model=NoteOut,
    status_code=status.HTTP_201_CREATED,
    summary="Создать новую заметку",
    description="Создает новую заметку для текущего пользователя",
    responses={
        201: {
            "description": "Заметка успешно создана",
            "model": NoteOut
        },
        401: {
            "description": "Не аутентифицирован",
            "content": {
                "application/json": {
                    "example": {"detail": "Not authenticated"}
                }
            }
        }
    }
)
async def create_note(
    note: NoteCreate,
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        new_note = Note(text=note.text, owner_id=current_user.id)
        session.add(new_note)
        await session.commit()
        await session.refresh(new_note)
        return new_note

@router.get(
    "/",
    response_model=list[NoteOut],
    summary="Получить список заметок",
    description="Возвращает список заметок текущего пользователя с возможностью пагинации и поиска",
    responses={
        200: {
            "description": "Список заметок успешно получен",
            "content": {
                "application/json": {
                    "example": [
                        {
                            "id": 1,
                            "text": "Купить молоко",
                            "created_at": "2024-03-20T10:30:00",
                            "owner_id": 1
                        }
                    ]
                }
            }
        }
    }
)
async def read_notes(
    current_user: User = Depends(get_current_user),
    skip: int = 0,
    limit: int = 100,
    search: str = None,
):
    async with async_session() as session:
        query = select(Note).where(Note.owner_id == current_user.id)

        if search:
            query = query.where(Note.text.ilike(f"%{search}%"))

        query = query.offset(skip).limit(limit)

        result = await session.execute(query)
        notes = result.scalars().all()

        return notes

@router.get(
    "/{note_id}",
    response_model=NoteOut,
    summary="Получить заметку по ID",
    description="Возвращает заметку по указанному ID, если она принадлежит текущему пользователю",
    responses={
        200: {
            "description": "Заметка успешно получена",
            "model": NoteOut
        },
        404: {
            "description": "Заметка не найдена",
            "content": {
                "application/json": {
                    "example": {"detail": "Note not found"}
                }
            }
        }
    }
)
async def read_note(
    note_id: int = Path(..., ge=1, description="ID заметки"),
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")
        return note

@router.put(
    "/{note_id}",
    response_model=NoteOut,
    summary="Обновить заметку",
    description="Обновляет текст заметки по указанному ID, если она принадлежит текущему пользователю",
    responses={
        200: {
            "description": "Заметка успешно обновлена",
            "model": NoteOut
        },
        404: {
            "description": "Заметка не найдена",
            "content": {
                "application/json": {
                    "example": {"detail": "Note not found"}
                }
            }
        }
    }
)
async def update_note(
    note_id: int = Path(..., ge=1, description="ID заметки"),
    note_update: NoteUpdate = None,
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        if note_update.text is not None:
            note.text = note_update.text

        session.add(note)
        await session.commit()
        await session.refresh(note)
        return note

@router.delete(
    "/{note_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Удалить заметку",
    description="Удаляет заметку по указанному ID, если она принадлежит текущему пользователю",
    responses={
        204: {
            "description": "Заметка успешно удалена"
        },
        404: {
            "description": "Заметка не найдена",
            "content": {
                "application/json": {
                    "example": {"detail": "Note not found"}
                }
            }
        }
    }
)
async def delete_note(
    note_id: int = Path(..., ge=1, description="ID заметки"),
    current_user: User = Depends(get_current_user)
):
    async with async_session() as session:
        note = await session.get(Note, note_id)
        if not note or note.owner_id != current_user.id:
            raise HTTPException(status_code=404, detail="Note not found")

        await session.delete(note)
        await session.commit()
        return None