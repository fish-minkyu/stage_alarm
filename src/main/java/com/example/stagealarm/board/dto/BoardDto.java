package com.example.stagealarm.board.dto;

import com.example.stagealarm.board.entity.ActivateEnum;
import com.example.stagealarm.board.entity.Board;
import com.example.stagealarm.board.entity.BoardComment;
import com.example.stagealarm.board.entity.Category;
import lombok.AllArgsConstructor;
import lombok.Getter;

import java.time.LocalDateTime;
import java.util.ArrayList;
import java.util.List;


@Getter
@AllArgsConstructor
public class BoardDto {
  private Long id;
  private String title;
  private String content;
  private ActivateEnum activate;
  private Long views;
  private Long userId;
  private String loginId;
  private Long categoryId;
  private LocalDateTime createdAt;
  private List<BoardCommentDto> comments;

  public static BoardDto fromEntity(Board entity) {
    List<BoardCommentDto> commentDtos = new ArrayList<>();
    if (!entity.getCommentList().isEmpty()) {
      for (BoardComment comment : entity.getCommentList()) {
        if (comment.getDepth() == 0)
          commentDtos.add(convertToDto(comment));
      }
    }

    return new BoardDto(
      entity.getId(),
      entity.getTitle(),
      entity.getContent(),
      entity.getActivate(),
      entity.getViews(),
      entity.getUserEntity().getId(),
      entity.getUserEntity().getLoginId(),
      entity.getCategory().getId(),
      entity.getCreatedAt(),
      commentDtos
    );
  }

  // BoardComment 엔티티를 BoardCommentDto로 변환
  private static BoardCommentDto convertToDto(BoardComment comment) {
    List<BoardCommentDto> childCommentDtos = new ArrayList<>();
    for (BoardComment childComment : comment.getChildComments()) {
      childCommentDtos.add(convertToDto(childComment));
    }

    return new BoardCommentDto(
      comment.getId(),
      comment.getContent(),
      comment.getDepth(),
      comment.getUserEntity().getId(),
      comment.getUserEntity().getLoginId(),
      comment.getBoard().getId(),
      childCommentDtos
    );
  }
}
