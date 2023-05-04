<?php

namespace App\Controller;

use App\Entity\Comment;
use App\Entity\Question;
use App\Form\CommentType;
use App\Form\QuestionType;
use DateTimeZone;
use Doctrine\ORM\EntityManagerInterface;
use Symfony\Bundle\FrameworkBundle\Controller\AbstractController;
use Symfony\Component\HttpFoundation\Request;
use Symfony\Component\HttpFoundation\Response;
use Symfony\Component\Routing\Annotation\Route;

class QuestionController extends AbstractController
{
    #[Route('/question/ask', name: 'ask_question')]
    public function ask(Request $request, EntityManagerInterface $em): Response
    {
        $question = new Question();

        $formQuestion = $this->createForm(QuestionType::class, $question);
        $formQuestion->handleRequest($request);

        if($formQuestion->isSubmitted() && $formQuestion->isValid()) {
            $question->setNbResponse(0);
            $question->setRating(0);
            $question->setCreatedAt(new \DateTimeImmutable(timezone: new DateTimeZone("Europe/Paris")));

            $em->persist($question);
            $em->flush();

            $this->addFlash('success', 'Votre question a ete ajoutée');

            return $this->redirectToRoute('home');
        }


        return $this->render('question/index.html.twig', ['form' => $formQuestion->createView()]);
    }

    #[Route('/question/{id}', name: 'show_question')]
    public function show(Request $request, Question $question, EntityManagerInterface $em) {

        $comment = new Comment();
        $commentForm = $this->createForm(CommentType::class, $comment);
        $commentForm->handleRequest($request);

        if ($commentForm->isSubmitted() && $commentForm->isValid()) {
            $comment->setCreatedAt(new \DateTimeImmutable(timezone: new DateTimeZone("Europe/Paris")));
            $comment->setRating(0);
            $comment->setQuestion($question);

            $em->persist($comment);
            $em->flush();

            $this->addFlash('success', 'Votre réponse a bien ete publiée');

            return $this->redirect($request->getUri());
        }

        return $this->render('question/show.html.twig', ['question' => $question, 'form' => $commentForm->createView()]);
    }
}
