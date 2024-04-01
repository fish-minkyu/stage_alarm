$(document).ready(function () {
    fetchArtists(0);
    fetchGenres();

    $('#search-input').on('submit', function (e) {
        e.preventDefault();
        const searchParam = $(this).find('input[name="param"]').val();
        console.log("searchParam,,,", searchParam);
        fetchDataWithSearch(searchParam);
    });

    // 좋아요 버튼 클릭 이벤트 처리
    $(document).on('click', '.like-btn', handleLikeButtonClick);

    // 아티스트 구독 버튼 클릭 이벤트 처리
    $(document).on('click', '.artist-subscribe-btn', handleArtistSubscribeButtonClick);

    // 장르 구독 버튼 클릭 이벤트 처리
    $(document).on('click', '.genre-subscribe-btn', handleGenreSubscribeButtonClick);

    let artistFilledTemplate = null;
    let previousState = null;
    function fetchArtists(page){
    const size = 9;
    $.ajax({
        url: "/artist",
        type: "GET",
        data: {
            "page": page,
            "size": size
        },
        success: function (data) {
            console.log("fetchData : ",data.content.toString());
            renderArtists(data);
            // 페이지네이션 생성
            renderPagination(data);

            previousState = data;
            // 페이지 이동 후 브라우저 히스토리에 상태 추가
            const newUrl = '/subscribe'; // 새로운 페이지 URL
            window.history.pushState({ path: newUrl }, '', newUrl);

            // 뒤로가기 버튼 이벤트 리스너 등록
            window.onpopstate = function (event) {
                if (previousState) {
                    renderArtists(previousState);
                    renderPagination(previousState);
                }
            };
        },
        error: function(xhr, status, error) {
            console.error("아티스트 AJAX 요청 실패: ", status, error);
        }
    });
}
    function fetchDataWithSearch(searchParam) {
        const page = 0;
        const size = 9;
        $.ajax({
            url: "/artist/search",
            type: "GET",
            data: {
                "param": searchParam,
                "page": page,
                "size": size
            },
            success: function (data) {
                console.log("fetchData : ",data.content.toString());
                renderArtists(data);
                renderPagination(data);
                // 페이지 이동 후 브라우저 히스토리에 상태 추가
                const newUrl = '/subscribe'; // 새로운 페이지 URL
                window.history.pushState({ path: newUrl }, '', newUrl);

                // 뒤로가기 버튼 이벤트 리스너 등록
                window.onpopstate = function (event) {
                    fetchArtists(0);
                    fetchGenres();
                };
            },
            error: function (xhr, status, error) {
                console.error("검색 AJAX 요청 실패: ", status, error);
            }
        });
    }

function fetchGenres() {
    $.ajax({
        url: "/genre",
        type: "GET",
        success: function (data) {
            renderGenres(data);
        },
        error: function (xhr, status, error) {
            console.error("장르 AJAX 요청 실패: ", status, error);
        }
    });
}

    const artistTemplate = $('#artistCardTemplate').html();
    function renderArtists(data) {
        const $artistList = $('#artistList .row');

        $artistList.empty();
        data.content.forEach(function (artist, index) {
            fillArtistTemplate(artistTemplate, artist);
            // 가로로 3개씩 채우기
            if (index % 3 === 0) {
                $artistList.append('<div class="w-100"></div>'); // 줄 바꾸기
            }
            $artistList.append(artistFilledTemplate);

            const $artistCard = $('[data-artist-id="' + artist.id + '"]');
            const $likeImage = $artistCard.find('.like-btn');

            console.log("좋아요했나요...?", artist.isLiked);

            if (artist.isLiked) {
                $likeImage.attr('src', 'images/like.png'); // 이미지 경로를 좋아요 이미지로 변경
            } else {
                $likeImage.attr('src', 'images/unlike.png'); // 이미지 경로를 좋아요 해제 이미지로 변경
            }
        });
    }

const genreTemplate = $('#genreCardTemplate').html();

let genreFilledTemplate=null;
function renderGenres(genres) {
    const $genreList = $('#genreList .row');

    $genreList.empty();
    $.each(genres, function (index, genre) {
        fillGenreTemplate(genreTemplate, genre);
        $genreList.append('<div class = "w-100"></div>');

        $genreList.append(genreFilledTemplate);
    });
}

function fillArtistTemplate(template, artist) {
    if (artist === null || artist.genres === null) {
        // 적절한 오류 처리 또는 초기화 코드
        console.error("data 또는 data의 특정 속성이 undefined입니다.");
        console.log(artist.genres);
        console.log(artist.name);
        // artist가 null이거나 genres가 null인 경우 빈 칸을 보여줌
        artist = {
            profileImg: "",
            name: "",
            age: "",
            gender: "",
            id: "",
            genres: [],
            likes: 0,
            isSubscribed: false
        };
    }
    // 장르 리스트를 문자열로 변환
    const genresStr = artist.genres.join(', ');
    console.log("genreStr: ",genresStr);
    const filledTemplate = template.replace(/{{artist.profileImg}}/g, artist.profileImg)
        .replace(/{{artist.name}}/g, artist.name)
        .replace(/{{artist.age}}/g, artist.age)
        .replace(/{{artist.gender}}/g, artist.gender)
        .replace(/{{artist.id}}/g, artist.id)
        .replace(/{{artist.genres}}/g, genresStr)
        .replace(/{{artist.artistLike}}/g, artist.likes)
        .replace(/{{buttonText}}/g, artist.isSubscribed ? '구독중' : '구독');
    artistFilledTemplate = filledTemplate;
}

function fillGenreTemplate(template, genre) {
    genreFilledTemplate = template.replace(/{{genre.name}}/g, genre.name)
        .replace(/{{genre.id}}/g, genre.id)
        .replace(/{{buttonText}}/g, genre.isSubscribed ? '구독중' : '구독');
}

function renderPagination(data) {
    const $pagination = $('.pagination');
    $pagination.empty();

    // 페이지네이션 생성
    const totalPages = data.totalPages;
    console.log("totalPages", totalPages);
    const currentPage = data.pageable.pageNumber + 1;
    console.log("currentPage", currentPage);
    const pagesToShow = 10; // 한 번에 보여줄 페이지 번호 개수

    const startPage = Math.floor((currentPage - 1) / pagesToShow) * pagesToShow + 1;
    const endPage = Math.min(startPage + pagesToShow - 1, totalPages);

    const $prevPageItem = $('<li class="page-item"><a class="page-link" href="#" aria-label="Previous"><span aria-hidden="true">&lt;</span></a></li>');
    $prevPageItem.click(function () {
        if (!$(this).hasClass('disabled')) {
            fetchArtists(currentPage - 2);
        }
    });
    if (currentPage === 1) {
        $prevPageItem.addClass('disabled');
    }
    $pagination.append($prevPageItem);

    for (let i = startPage; i <= endPage; i++) {
        const $pageItem = $('<li class="page-item"><a class="page-link" href="#">' + i + '</a></li>');
        if (i === currentPage) {
            $pageItem.addClass('active');
        }
        $pageItem.click(function () {
            if (!$(this).hasClass('active')) {
                fetchArtists(i - 1);
            }
        });
        $pagination.append($pageItem);
    }

    const $nextPageItem = $('<li class="page-item"><a class="page-link" href="#" aria-label="Next"><span aria-hidden="true">&gt;</span></a></li>');
    $nextPageItem.click(function () {
        if (!$(this).hasClass('disabled')) {
            fetchArtists(currentPage);
        }
    });
    if (currentPage === totalPages) {
        $nextPageItem.addClass('disabled');
    }
    $pagination.append($nextPageItem);
}

// 좋아요 버튼 클릭 이벤트 핸들러
function handleLikeButtonClick() {
    const artistId = $(this).data('artist-id');
    const $likeImage = $(this);

    // 이미지 변경
    if ($likeImage.attr('src') === 'images/unlike.png') {
        $likeImage.attr('src', 'images/like.png');
    } else {
        $likeImage.attr('src', 'images/unlike.png');
    }

    // 좋아요 AJAX 요청
    $.ajax({
        url: "/artist/" + artistId + "/like",
        type: "POST",
        contentType: "application/json",
        success: function (data) {
            // 좋아요 수 업데이트
            const updatedLikes = data.likes;
            console.log(updatedLikes);

            // 해당 아티스트 카드를 찾아서 좋아요 수 업데이트
            const $artistCard = $likeImage.closest('.artist-card');
            $artistCard.find('.likes-count').text(updatedLikes);
            console.log('좋아요 클릭 - 아티스트 ID:', artistId);
        },
        error: function (xhr, status, error) {
            console.error("아티스트 좋아요 AJAX 요청 실패: ", status, error);
        },
    });
}

// 아티스트 구독 버튼 클릭 이벤트 핸들러
function handleArtistSubscribeButtonClick() {
    const artistId = $(this).data('artist-id');
    const $subscribeBtn = $(this);

    // 버튼 텍스트 변경
    const buttonText = $subscribeBtn.text();
    if (buttonText === '구독') {
        $subscribeBtn.text('구독중');
    } else {
        $subscribeBtn.text('구독');
    }

    // 아티스트 구독 AJAX 요청
    $.ajax({
        url: "/artist/" + artistId + "/subscribe",
        type: "POST",
        contentType: "application/json",
        success: function (data) {
            console.log('아티스트 구독 클릭 - 아티스트 ID:', artistId);
            // 구독 상태 업데이트
        },
        error: function (xhr, status, error) {
            console.error("아티스트 구독 AJAX 요청 실패: ", status, error);
        }
    });
}

// 장르 구독 버튼 클릭 이벤트 핸들러
    function handleGenreSubscribeButtonClick() {
        const genreId = $(this).data('genre-id');
        const $genreBtn = $(this);

        // 버튼 텍스트 변경
        const buttonText = $genreBtn.text();
        if (buttonText === '구독') {
            $genreBtn.text('구독중');
        } else {
            $genreBtn.text('구독');
        }

        // 장르 구독 상태를 서버에 업데이트하는 AJAX 요청
        $.ajax({
            url: "/genre/" + genreId + "/subscribe",
            type: "POST",
            contentType: "application/json",
            success: function (data) {
                // 성공 시 처리
                console.log('장르 구독 클릭 - 장르 ID:', genreId);
            },
            error: function (xhr, status, error) {
                console.error("AJAX 요청 실패: ", status, error);
            }
        });
    }
});
