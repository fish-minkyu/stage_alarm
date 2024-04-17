package com.example.stagealarm.genre.repo;

import com.example.stagealarm.genre.entity.Genre;
import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;
import java.util.Optional;

public interface GenreRepository extends JpaRepository<Genre, Long> {
  Optional<Genre> findByName(String name);

}
