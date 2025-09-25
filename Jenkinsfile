pipeline {
    agent any

    environment {
        ENV_FILE = '.env'

        // DockerHub 사용자명 및 이미지 이름 (필요에 맞게 변경)
        DOCKER_IMAGE = 'anministar/mesmenu-app'
        // GitHub 자격증명 ID (Jenkins에 등록한 토큰 ID)
        GITHUB_CREDENTIALS_ID = 'github-Username-PW'
        // DockerHub 자격증명 IÓD (Jenkins에 등록한 DockerHub ID/PW)
        DOCKERHUB_CREDENTIALS_ID = 'docker-hub-credentials'

        DB_CREDENTIALS_ID = 'db-credentials'

        // OATUH LOGIN - KAKAO
        KAKAO_CREDENTIALS_ID = 'kakao-credentials'


    }

    stages {
         stage('1. Test Git Access with Credentials') {
            steps {
              withCredentials([usernamePassword(
                credentialsId: env.GITHUB_CREDENTIALS_ID,
                usernameVariable: 'GITHUB_USER',
                passwordVariable: 'GITHUB_TOKEN'
              )]) {
                sh 'git ls-remote https://$GITHUB_USER:$GITHUB_TOKEN@github.com/mesmenu/Mes_Menu.git'
              }
            }
         }

        stage('2. Git Checkout') {
          steps {
            // GitHub 저장소에서 코드 받기
            git credentialsId: env.GITHUB_CREDENTIALS_ID,
                url: 'https://github.com/mesmenu/Mes_Menu.git',
                branch: 'main'
          }
        }
        stage('Generate .env') {
		      steps {
		        withCredentials([
		          usernamePassword(
		            credentialsId: env.DB_CREDENTIALS_ID,
		            usernameVariable: 'DB_USER',
		            passwordVariable: 'DB_PASS'
		          ),
		          usernamePassword(
                    credentialsId: env.KAKAO_CREDENTIALS_ID,
                    usernameVariable: 'KAKAO_CLIENT_ID',
                    passwordVariable: 'KAKAO_CLIENT_SECRET'
                  )
		        ]) {
		         sh """
                         cat > .env <<EOF
DB_DRIVER=com.mysql.cj.jdbc.Driver
DB_URL=jdbc:mysql://db:3306/mesmenu_db?serverTimezone=Asia/Seoul
DB_USERNAME=${DB_USER}
DB_PASSWORD=${DB_PASS}

KAKAO_CLIENT_ID=${KAKAO_CLIENT_ID}
KAKAO_CLIENT_SECRET=${KAKAO_CLIENT_SECRET}
EOF
                       """
		            echo ".env 파일 생성 완료"
		        }
		      }
		    }

         stage('3. yq 설치 (필요 시)') {
                    steps {
                        // yq를 Jenkins Agent 내 시스템 PATH에 포함시켜 설치
                        sh """
                        if ! command -v yq &> /dev/null; then
                          echo 📦 yq 설치 중...
                          mkdir -p /tmp/bin
                          curl -L https://github.com/mikefarah/yq/releases/latest/download/yq_linux_amd64 -o /tmp/bin/yq
                          chmod +x /tmp/bin/yq

                          export PATH="/tmp/bin:$PATH"
                          echo ✅ yq 버전 확인:
                          /tmp/bin/yq --version

                          yq --version
                          echo "✅ yq 설치 완료"
                        else
                          echo "✅ yq 이미 설치되어 있음"
                        fi
                        """
                    }
                }
        stage('4. Build Docker Image') {
            steps {
                // 도커 이미지 빌드, 태그에는 git 커밋 short hash 사용
                script {
                    def commitHash = sh(script: 'git rev-parse --short HEAD', returnStdout: true).trim()
                    env.IMAGE_TAG = "${env.DOCKER_IMAGE}:${commitHash}"
                }
                sh "docker build -t ${env.IMAGE_TAG} ."
            }
        }

        stage('5. Push Docker Image') {
            steps {
                // DockerHub 로그인 후 이미지 푸시
                withCredentials([usernamePassword(credentialsId: env.DOCKERHUB_CREDENTIALS_ID,
                                                  usernameVariable: 'DOCKER_USER',
                                                  passwordVariable: 'DOCKER_PASS')]) {
                    sh '''
                      echo "$DOCKER_PASS" | docker login -u "$DOCKER_USER" --password-stdin
                      docker push ${IMAGE_TAG}
                      docker logout
                    '''
                }
            }
        }

        stage('6. Deploy with docker-compose') {
            steps {
                // docker-compose.yml 내 이미지 태그를 최신 빌드한 이미지로 치환 후 배포
                sh '''
                  # docker-compose.yml 내 services: 안의 app: 안의 image: 이미지 태그 바꾸기 (예: yp 사용)
                  /tmp/bin/yq eval '.services.app.image = "'${IMAGE_TAG}'"' -i docker-compose.yml

                  # 1번
                  # 실행 중인 컨테이너를 down, 명령어 실행안돼도 오류 x
                  docker-compose down || true
                  docker-compose up -d

                  # 2번
                  # app 서비스만 강제 재생성, 의존 서비스 건들지 x
                  # --no-deps        : depends_on 서비스(== depends_on, mysql_db, redis 등) 재시작 x
                  # --force-recreate : 이미지 변경 여부와 무관하게 무조건 컨테이너 새로 만듦.
                  # docker-compose up -d --no-deps --force-recreate app
                '''
            }
        }
    }
}