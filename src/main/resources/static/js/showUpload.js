$("#posterImage").on("change", function(){
    const fileInput = $("#posterImage")[0];
    const files = fileInput.files;
    const reg = /(.*?)\.(jpg|bmp|jpeg|png|JPG|BMP|JPEG|PNG)$/;
    const maxSize = 5 * 1024 * 1024;

    // var file = event.target.files[0];
    const imageContainer = $("#imageContainer");
    imageContainer.empty();

    for (let i = 0; i < files.length; i++) {
        const file = files[i];
        const reader = new FileReader();
        // reader.readAsDataURL(file);

        reader.onload = (function (file) {
            return function (e) {
                // 미리보기 이미지의 크기 조절
                var img = $("<img>").attr("src", e.target.result).css({
                    "max-width": "200px",
                    "max-height": "200px",
                    "margin": "5px"  // 이미지 간격을 조절하기 위한 스타일
                });
                // 이미지를 이미지 컨테이너에 추가
                imageContainer.append(img);
            };
        })(file);

        if (!file.name.match(reg)) {
            alert("이미지 파일만 업로드 가능합니다. ");
            fileInput.value = "";
            return;
        } else if (file.size >= maxSize) {
            alert("파일 사이즈는 5MB까지 가능합니다. ");
            fileInput.value = "";
            return;
        }
        reader.readAsDataURL(file);
    }
});

// 기존에 추가된 아티스트 목록을 저장할 배열
let foundArtists = [];
let foundGenres = [];
let artistListHtml = '';
let genreListHtml= '';
const artistTemplate = $('#artistList').html();
const genreTemplate = $('#genreList').html();
let selectedArtists = []; // 선택된 아티스트 이름을 저장할 배열
let selectedGenres = [];

$(document).ready(function () {
    console.log(foundArtists.toString());
    $.ajax({
        url: "/artist",
        type: "GET",
        success: function (response) {
            // 아티스트 정보를 반복하여 HTML에 추가
            $.each(response, function (index, artist) {
                let filledTemplate = artistTemplate.replace(/{{artist.id}}/g, artist.id); // artist.id를 템플릿에 추가
                filledTemplate = filledTemplate.replace(/{{artist.name}}/g, artist.name);
                filledTemplate = filledTemplate.replace(/{{artist.name}}/g, artist.name); // 버튼의 data-artist-name 속성에도 적용
                filledTemplate = filledTemplate.replace(/{{artist.genre.name}}/g, artist.genres)
                console.log(artist.genres.get(0));
                artistListHtml += filledTemplate;
                foundArtists.push(artist.name);
            });

            // HTML에 추가된 아티스트 리스트를 추가
            $('#artistList').html(artistListHtml);
        },
        error: function(xhr, status, error) {
            console.error('Failed to load artists: ', error);
        }
    });

    $.ajax({
        url: "/genre",
        type: "GET",
        success: function (response) {
            // 장르 정보를 반복하여 HTML에 추가
            $.each(response, function (index, genre) {
                let filledTemplate = genreTemplate.replace(/{{genre.id}}/g, genre.id); // artist.id를 템플릿에 추가
                filledTemplate = filledTemplate.replace(/{{genre.name}}/g, genre.name);
                filledTemplate = filledTemplate.replace(/{{genre.name}}/g, genre.name); // 버튼의 data-artist-name 속성에도 적용
                genreListHtml += filledTemplate;
                foundGenres.push(genre.name);
            });

            // HTML에 추가된 아티스트 리스트를 추가
            $('#genreList').html(genreListHtml);
        },
        error: function(xhr, status, error) {
            console.error('Failed to load artists: ', error);
        }
    });
});


$(document).on('click', '.select-artist-btn', function () {
    const artistName = $(this).data('artist-name');
    const artistGenre = $(this).data('artist-genre');


    // 이미 선택된 아티스트인지 확인
    if (!selectedArtists.includes(artistName)) {
        selectedArtists.push(artistName); // 배열에 아티스트 이름 추가
    }

    // 선택된 모든 아티스트의 이름을 표시
    $('#selectedArtistName').text(selectedArtists.join(', ')); // 선택된 모든 아티스트의 이름을 쉼표로 구분하여 표시
});

$(document).on('click', '.select-genre-btn', function () {
    const genreName = $(this).data('genre-name');
    console.log('genreName -', genreName);

    // 이미 선택된 아티스트인지 확인
    if (!selectedGenres.includes(genreName)) {
        selectedGenres.push(genreName); // 배열에 아티스트 이름 추가
    }

    // 선택된 모든 아티스트의 이름을 표시
    $('#selectedGenreName').text(selectedGenres.join(', ')); // 선택된 모든 아티스트의 이름을 쉼표로 구분하여 표시
});




$('#addArtistBtn').click(function() {
    $('#addArtistForm').toggle(); // 입력 폼을 토글하여 보이기/숨기기
});

$('#addNewArtistBtn').click(function() {
    const newArtistName = $('#newArtistName').val();

    if (newArtistName === '') {
        alert('아티스트 이름을 입력하세요.');
        return;
    }
    if (foundArtists.includes(newArtistName)) {
        alert('이미 존재하는 아티스트입니다.');
        return;
    }

    // 새 아티스트를 리스트에 추가하는 작업을 수행
    // 예를 들어, AJAX 요청을 보내거나 새로운 HTML 요소를 생성하여 리스트에 추가할 수 있습니다.
    // 여기서는 간단하게 콘솔에 출력하도록 하겠습니다.
    $.ajax({
        url: "/artist",
        type: "POST",
        contentType: "application/json",
        data: JSON.stringify({
            name: newArtistName
        }),
        success: function (response) {

            foundArtists.push(newArtistName);
            $('#newArtistName').val('');

            let filledTemplate = artistTemplate.replace(/{{artist.id}}/g, response.id); // artist.id를 템플릿에 추가
            filledTemplate = filledTemplate.replace(/{{artist.name}}/g, response.name);
            filledTemplate = filledTemplate.replace(/{{artist.name}}/g, response.name); // 버튼의 data-artist-name 속성에도 적용
            artistListHtml += filledTemplate;
            console.log('새 아티스트 추가:', newArtistName);
            $('#artistList').html(artistListHtml);

        },
        error: function (xhr, status, error) {
            console.error('Failed to load artists: ', error);
        }
    });
});