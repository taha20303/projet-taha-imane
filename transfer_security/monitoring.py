from pathlib import Path


def get_stream_size(stream):
    """Taille d'un flux de fichier, sans modifier sa position finale."""
    position = stream.tell()
    stream.seek(0, 2)
    size = stream.tell()
    stream.seek(position)
    return size


def collect_transfer_metadata(
    file,
    username,
    destination,
    sensitivity,
    file_size=None
):
    """Construit les métadonnées d'un transfert.

    file_size : taille déjà connue (ex. Path.stat().st_size). Si absente,
    elle est lue depuis le flux du fichier.
    """
    filename = Path(file.filename or "unknown").name

    if file_size is None:
        file_size = get_stream_size(file.stream)

    return {
        "username": username,
        "filename": filename,
        "destination": str(destination).lower(),
        "file_size": int(file_size),
        "sensitivity": str(sensitivity).upper(),
    }