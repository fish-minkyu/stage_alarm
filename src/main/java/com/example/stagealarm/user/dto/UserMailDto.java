package com.example.stagealarm.user.dto;

import lombok.*;

@Getter
@Setter
@Builder
@NoArgsConstructor
@AllArgsConstructor
public class UserMailDto {
    private String email;
    private String subject;
    private String text;
}
