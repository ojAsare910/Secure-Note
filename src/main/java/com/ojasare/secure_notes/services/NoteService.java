package com.ojasare.secure_notes.services;

import com.ojasare.secure_notes.models.Note;

import java.util.List;

public interface NoteService {
    Note createNoteForUser(String username, String content);

    Note updateNoteForUser(Long noteId, String content, String username);

    List<Note> getNotesForUser(String username);

    List<Note> getAllNotes();
}

