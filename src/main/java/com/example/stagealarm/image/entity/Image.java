package com.example.stagealarm.image.entity;

import com.example.stagealarm.BaseEntity;
import com.example.stagealarm.board.entity.Board;
import com.fasterxml.jackson.annotation.JsonBackReference;
import jakarta.persistence.*;
import lombok.*;

@Getter
@Builder
@Entity
@NoArgsConstructor
@AllArgsConstructor
public class Image extends BaseEntity {
  @Column(nullable = false)
  private String imgUrl;

  @ManyToOne(fetch = FetchType.LAZY)
  @JsonBackReference
  @Setter
  private Board board;
}
