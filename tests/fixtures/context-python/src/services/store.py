from sqlalchemy.orm import Session

def save(session: Session) -> None:
    session.commit()
